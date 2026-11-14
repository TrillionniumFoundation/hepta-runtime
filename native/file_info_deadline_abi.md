# Fixed native inspection deadline

The seven-image local read profile runs `file_info` through a fixed native
watchdog. The HIA IO owner still determines validation, traversal, complete-file
hashing, metadata capture, error precedence, cleanup and the response bytes.
The boundary adapter supplies an owned worker, an absolute monotonic deadline
and a checked result handoff. It does not contain a file-info implementation or
invoke a Python, Rust, shell, SSH or dynamically loaded semantic fallback.

The production duration is exactly 30 seconds. There is no MCP parameter,
environment variable or command-line option that changes it. The separate
200 ms native pipe fixture is a test of actual kernel blocking and cancellation;
it is not a production timeout setting.

## HIA transitions

The ordinary effect envelope remains at IO workspace offset 256. These two
actions are available only to the pinned IO image in module 3, with flags 3,
call mask 4 and an 8 MiB private workspace.

| Action | HIA state and request | Native completion |
|---|---|---|
| 10, start | State 55; guard state at 2192 is zero; handle, offset, size and argument are zero | Only the worker receives success, with result, errno and returned handle all zero. A parent timeout receives `ETIMEDOUT` (110); another setup or worker failure receives its positive errno. |
| 12, finish | State 56; guard state is two; stored extent at 2200 equals the request size, 128–75,776; other arguments are zero | After a complete accepted handoff, the parent acknowledges that exact extent, with errno and returned handle zero. |

HIA changes guard state from zero to one after a successful start. It performs
the original operation and all finalizers, writes the complete typed response,
sets guard state to two and yields finish. HIA changes the state back to zero
only after the finish acknowledgement. Start timeout produces IO status 15;
other guard failures produce status 19. The service maps these typed failures
to its declared local error strings and exposes no partial metadata or digest.

Capacity and request framing are checked before start. The deadline begins
immediately before the worker is created and covers target traversal, every
file and xattr operation, native SHA calls, finalizers, response serialization,
worker staging and parent validation. Fixed guard setup precedes the deadline.

## Process and descriptor ownership

The parent has one persistent administrator-owned root descriptor. At start,
the adapter verifies that this is the only active descriptor-table entry and
that all request handles are zero. It snapshots the root token, table entries,
active caller context, both sequence counters and the frame-entry budget.

The worker is created with `fork`. The service and HIA workspaces are private
copy-on-write mappings. A separate anonymous shared mapping is used only for
the eventual handoff. The worker installs `PR_SET_PDEATHSIG(SIGKILL)` and checks
that its parent identity is unchanged. It closes inherited standard streams,
except when one of those raw descriptor numbers is the registered root itself.
Consequently a valid launch with stderr closed can retain a root at raw fd 2.
No raw worker descriptor number is accepted as a new parent capability.

The native parent retains the worker PID until a specific-PID `wait4` reaps it.
The adapter explicitly restores the default SIGCHLD disposition before fork,
so an inherited ignored disposition cannot silently auto-reap the worker and
permit PID reuse before cancellation. The watchdog never signals a process
group, a caller-supplied PID or an unrelated process.

## Absolute waiting and cancellation

The parent computes one absolute `CLOCK_MONOTONIC` deadline. Before every
`ppoll`, including retries after interruption, it recomputes the remaining
interval from that original deadline. The worker signals a private pipe only
after it has staged the complete result. A closed pipe without a complete
commit or another worker-internal failure maps to `EIO` (5). A ready worker is
also sent cancellation and subjected to a nonblocking reap attempt before
admission; the parent validates
only its fully staged result, without allowing it to resume outer service code.

At timeout, the parent sends SIGKILL only to its owned worker, attempts a
nonblocking reap, discards the shared staging mapping and acknowledges the
original start request with errno 110. Its live IO workspace, output, root
descriptor, module-call counter and descriptor generations have not been
replaced. The start effect sequence has already been consumed, so its typed
failure and the next request remain synchronized.

Cancellation does not wait synchronously for an uninterruptible kernel
operation to finish. If the worker cannot yet be reaped, its PID remains owned
and the adapter admits no second inspection worker until a later nonblocking
reap succeeds. A subsequent inspection receives `EBUSY` while that one pending
worker remains; ordinary protocol and other existing read operations can
continue. Process shutdown also cancels the owned worker. This bounds pending
workers without claiming that user space can force immediate completion of a
kernel operation in an uninterruptible sleep.

## Atomic result admission

The shared mapping contains a fixed header, an 8 MiB IO workspace snapshot and
at most 75,776 output bytes. It is separate from the parent's live workspace
and from every service output region. The worker writes its commit marker last
and sends a one-byte pipe notification; it then exits without resuming an outer
service controller.

Before importing any result, the parent validates all of the following:

- The complete marker, bounded output extent, original start sequence, exact
  active depth and unchanged caller identity, pointers and capacities.
- The IO effect counter in both the workspace and adapter, and the IO codec
  call counter in both the workspace and module table. No other module call
  sequence may advance in the worker.
- The exact active caller-context stack, apart from the admitted IO call
  sequence, and the accumulated root-frame entry count within its existing
  bound.
- The unchanged root token, root descriptor, root generation, normalized root
  bytes and HIA root-authority fields. All request handles must be zero.
- Every non-root descriptor-table slot must be closed. Only the generations of
  such closed slots can be imported; worker-only raw descriptor numbers are
  never copied into the live parent table.
- The complete HIA finish state and effect envelope, with no stale completion,
  returned handle, reserved field or mismatched result extent.
- The absolute deadline, again after validation and immediately before commit.

The commit point follows the final deadline check. From that point, the parent
performs bounded anonymous-memory copies and updates only the admitted IO
workspace, current output, counter pairs, frame budget and closed generations.
It acknowledges the copied finish envelope with the exact result extent.
No target syscall is performed while importing the result. Any failure before
that point discards the staging mapping and leaves the original start snapshot
in place.

## Source and evidence boundary

`composition_packer.hepta` owns the complete static ELF adapter bytes. The
composition manifest pins that HIA packer and all seven native images. The
development assembly is authoring input; it is not interpreted or loaded by
the resulting service. The executable has no dynamic loader, libc dependency
or Python runtime dependency.

The qualification evidence keeps three distinct categories:

| Test | What it establishes |
|---|---|
| `test_file_info_deadline_state.py` | Actual HIA guard transitions with explicitly synthetic guard completions, including failure cleanup and replay refusal. |
| `test_native_deadline_probe.py` | An actual native worker observed sleeping in empty-pipe `SYS_read`, followed by native timed cancellation and reaping. |
| `test_file_info_guard.py` | The actual seven-image service at its fixed 30-second duration, with a worker read or xattr syscall held by Linux notification; timeout rollback, worker reaping, persistent-root custody and subsequent original-result comparisons. |

Normal `file_info` tests additionally compare exact compact result text against
the unchanged original helpers, including real Linux xattrs and ACLs, complete
hashes beyond 1 MiB, separate fingerprint/capture modes and 4,096-byte target
paths. Syscall-fault controls preserve the original metadata ordering and last
close-error precedence. None of these tests replaces production business logic
with a test oracle.

This owner is for the explicitly named Linux local-read profile. It adds one
implemented read-only handler to that profile and does not close remote SSH
transport, other platform metadata, write tools or the remaining runtime tool
inventory.
