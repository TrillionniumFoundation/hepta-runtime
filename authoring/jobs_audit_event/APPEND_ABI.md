# Private jobs audit continuation boundary

This is a development interface. Public route activation and removal of the
original implementation remain unqualified until the complete append, namespace,
failure, lifecycle and public-route comparisons have passed.

## Callable transport

All calls use Linux x86-64 SysV. Create takes `(owner_entry, canonical_entry,
sha_entry, namespace_entry, errno_entry, at_secure)` and returns an opaque context or a negative errno.
`jobs_audit_invoke(context, request, request_size)` returns the response extent or
the original HIA refusal/fault code. `jobs_audit_output(context)` returns the
borrowed response pointer. `jobs_audit_release(context)` ends that borrow.
`jobs_audit_destroy(context)` closes every live descriptor and frees storage;
it must refuse a live result borrow. There is one shared process owner and an
exclusive invocation/result lease. An invocation cannot replace a borrowed
result. Terminal native admission, allocation, trap and lifecycle failures clear
positive publication readiness. Raw syscall errno is returned only in the action
receipt: HIA decides whether it is a handled control result, a retry, a cold
fallback or an append failure. For example, mkdir EEXIST and inotify EAGAIN do
not independently revoke a valid previous proof. The HIA failure paths explicitly
clear readiness; the transport must not make that business decision.

The canonical image is the unchanged `native/local_canonical.hepta`; its existing
13-effect dispatcher and two private descriptors must be preserved by an exact,
reviewable source transformation. Its error/cleanup paths return to this caller;
they must not exit the embedding runtime. The SHA image is unchanged
`native/binary_codec.hepta` (its precise streaming wire is still being checked).

Request `HBAUQ001` is 64 bytes plus payload: version=1 at 8; state-root, host,
subject and operation lengths at 16,24,32,40; zeros at 48,56. Payload order is
state-root, host, subject, operation. The only operation is `write`. The action is
fixed `native_binary_write`. The state root comes from installed configuration,
not tool JSON. Time is obtained from the real clock effect.

Result `HRCFGM01`: status at 8, category at 16 (zero), payload length at 24.
Status zero and an empty payload is the only permission to proceed with SSH.
Status one carries the original error text. Native refusals, resource failures,
invalid continuations and traps cannot become an empty successful result.

## Owner buffers

The owner uses borrowed `(input, input_length, output, output_capacity,
workspace, workspace_capacity)`, with a minimum 8192-byte workspace. Initial
output capacity may be 16384. Workspace grows on `0xffffffef`; required capacity
is at workspace+208. Output grows on `0xffffffee`; required capacity is at +216.
Growth preserves the entire existing workspace, input bytes and current state.
The owner does not use an allocation failure as business success. No transport
may substitute a smaller semantic request limit for checked allocation failure.

Persistent fields: magic +0, phase +8, effect sequence +16. Positive readiness
at +128 is cleared by the transport on any abort. All other header fields are
HIA-owned. Action is 128 bytes at workspace+256. Syscall result structures and
data are written only into the effect's explicitly admitted output spans.

## Effects

An effect returns `0xfffffff0`. Action fields are eight-byte LE words:

| Offset | Meaning |
| --- | --- |
| 0 | `HJAUA001` |
| 8 | Monotonically increasing sequence, equal to workspace+16 |
| 16 | Closed opcode below |
| 24,32,40,48,56 | Five operation arguments |
| 64 | Acknowledged sequence; zero before the effect |
| 72 | Nonnegative result (or required child-output extent) |
| 80 | Positive errno, zero on success |
| 88,96,104,112,120 | Reserved zeros |

Each new effect sequence must be the preceding transport sequence plus one,
without wrap. Before dispatch, acknowledgement/result/errno and reserved words
are zero. After dispatch, only acknowledgement/result/errno and declared output
spans may change. Kernel EINTR, partial writes and retry/error decisions are
reported to HIA. The transport does not decide their policy.

| Op | Effect | Arguments |
| --- | --- | --- |
| 1 | clock_gettime(CLOCK_REALTIME) | output offset, exact extent 16, 0,0,0 |
| 2 | mkdir | path offset, byte length excluding NUL, mode,0,0 |
| 3 | newfstatat(AT_FDCWD) | path offset, length, 144-byte stat output offset, flags,0 |
| 4 | openat(AT_FDCWD) | path offset, length, flags, mode,0 |
| 5 | fstat | opaque handle, 144-byte stat output offset,0,0,0 |
| 6 | geteuid | 0,0,0,0,0 |
| 7 | fchmod | opaque handle, mode,0,0,0 |
| 8 | write (one syscall) | opaque handle, byte offset, extent,0,0 |
| 9 | fdatasync | opaque handle,0,0,0,0 |
| 10 | fsync | opaque handle,0,0,0,0 |
| 11 | close | opaque handle,0,0,0,0 |
| 12 | inotify_init1 | flags,0,0,0,0 |
| 13 | inotify_add_watch via `/proc/self/fd/<fd>` | event handle, directory handle, mask,0,0 |
| 14 | read (one syscall) | opaque handle, byte output offset, capacity,0,0 |
| 15 | inotify_rm_watch | event handle, watch descriptor,0,0,0 |
| 16 | unchanged raw canonical HIA child | input offset, extent, output offset, capacity,0 |
| 17 | getdents64 | opaque handle, output offset, capacity,0,0 |
| 18 | openat(directory, ".") | directory handle, flags,0,0,0 |
| 19 | unchanged SHA HIA child | input offset, extent, output offset, capacity,0 |
| 20 | fcntl(F_DUPFD_CLOEXEC,0) | opaque handle,0,0,0,0 |
| 21 | HIA namespace owner | 0,0,0,0,0 |
| 22 | unchanged HIA Linux error-text child | input offset, extent, output offset, capacity,0 |

Open, inotify-init and dup return fresh monotonically increasing opaque handles;
they never return a raw process descriptor. At least 256 simultaneous entries
are required for the original 128-watch namespace cache and its descriptor pins.
All handle operands resolve only through this context's live registry. Closing
retires the handle permanently, including close errors; do not retry close.
Registry exhaustion and handle/sequence wrap are native resource/fault results.

Path spans include a separately checked trailing NUL, have no interior NUL, and
must be wholly within the borrowed workspace. Output/input spans are checked
with subtraction before pointer arithmetic. Syscall flags and modes are passed
as the exact HIA-supplied scalar after checking their Linux field widths.
The closed operation table provides no exec, arbitrary syscall, external file
descriptor import, network access or caller-selected child image.

For child calls, validate full child response and return its exact extent. When
the extent exceeds the requested output capacity, return the required extent
without copying partial output; the HIA owner grows its span and retries. The
unchanged child owns all canonicalization/hash semantics and internal growth.

Transport-owned registry cleanup must run on destruction and native faults.
The final success result retains only the descriptors held by the HIA readiness
and namespace proof. Ordinary failures cannot retain a warm publication proof.

Opcode 21 enters the separate namespace HIA image with the same immutable input,
output and shared workspace. Acknowledge entry before invoking it. Its effects
continue the same global sequence/acknowledgement chain. It returns
`0xffffffed` to resume the enclosing audit HIA owner, whose continuation phase
was selected by HIA. Do not restore the older opcode-21 acknowledgement over a
newer effect's acknowledgement. The transport does not inspect audit/namespace
business phases. This split preserves the original 8192-operation module bound.

SHA input is `HRCODEC1`, operation word, zero word, payload. Operation 3 has no
payload and returns the original 128-byte `HSHA2561` initial state. Operation 4
takes that state followed by a chunk of at most 1 MiB and returns the new
128-byte state. Operation 5 takes the state and returns the 32-byte digest.
Use an independent 4096-byte SHA workspace and at least 128 bytes of output.

The unchanged `native/directory_errno.hepta` is the error-text image. Its input
is `HMDERQ01` followed by errno (1..4095). Output is `HMDERR01`, errno, byte
length, then the original complete Linux error text. Use at least 4096 bytes
of output and 8 bytes of workspace (4096 is convenient).

Raw canonical input has a 64-byte header: `HRCNLQ01`, version 1, path length,
PWD length 0, PWD-present 0, three reserved zeros, then the absolute path bytes.
Result is `HRCNLR01`, status, payload length, errno, then payload. No PWD or
process cwd is needed for the admitted absolute configuration paths.
