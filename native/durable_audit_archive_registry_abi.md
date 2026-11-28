# Durable Audit Archive registry private ABI v1

This component preserves the lifetime domain of the original
`src/mcp/runtime/request_archive_store.rs` registry: one registry per runtime,
keyed by the actual retained audit-root and legacy-directory identities. It is
not an audit record database, a filesystem admission policy, or a public MCP
handler.

## Authority and lifetime

The HIA policy owns identity allocation, weak-entry pruning, strong counts,
the in-progress open reservation, and poison/fatal classification. The native
capability owns its actual mutex, anonymous storage, allocation growth and
wake sequence. Every session of the same runtime must borrow the same
capability. Creating a capability for each request would violate this ABI.

The four identity words are trusted private inputs from the admitted, still
held root and legacy directory handles: root device, root inode, legacy device,
legacy inode. JSON-supplied identities or descriptors are not accepted at this
boundary. The physical Archive owner must remain attached to exactly one live
token. Its retained layout state is shared by every strong holder, including
tickets created before v12 activation.

A begin-open reservation is a real strong reference. It retains the registry
open gate until the original load/recovery/size transition/fence sequence has
actually completed. Completion failure drops only that reservation. Existing
strong callers may clone or drop while another open is pending; the reservation
itself is not a published caller handle. A last strong drop requires retirement
of the exact physical owner. The weak table does not retain file descriptors.

Physical owner construction, attachment, its final cleanup, ContentWatchSet,
and public routing are separate integration obligations. The isolated policy
and native mutex controls do not certify those obligations.

## Policy call

The HIA entry uses the existing six-argument flat ABI:
`(input, input_length, output, output_capacity, workspace, workspace_capacity)`.
All words below are little-endian unsigned 64-bit words unless stated otherwise.

The request is exactly 96 bytes:

| Offset | Field |
| --- | --- |
| 0 | ASCII HRAARQ01 |
| 8 | Operation |
| 16, 24, 32, 40 | Four retained-directory identity words, only for begin |
| 48 | Token |
| 56 | Completion accepted flag, only for complete |
| 64..95 | Four zero reserved words |

| Operation | Meaning |
| --- | --- |
| 0 | Initialize entirely zeroed storage |
| 1 | Begin open, prune expired weak entries and reserve one strong reference |
| 2 | Complete the exact pending open; argument 1 succeeds, 0 drops its reservation |
| 3 | Clone an existing published strong reference |
| 4 | Drop one existing published strong reference |
| 5 | Inspect global counts when token is zero, otherwise inspect that token |
| 6 | Explicit native registry poison event; release only the pending reservation |

Only begin carries identity words. Only complete carries a nonzero argument,
and that argument must be exactly zero or one. Unknown operations, bad lengths,
reserved fields and malformed state are rejected.

A successful policy call returns 112 and writes exactly 112 response bytes:

| Offset | Field |
| --- | --- |
| 0 | ASCII HRAARR01 |
| 8 | Status |
| 16 | Relevant token |
| 24 | Its strong count |
| 32 | Newly created owner flag |
| 40 | Exact last-strong retirement flag |
| 48 | Required storage length, for storage growth only |
| 56 | Number of entries with live strong references |
| 64 | Number of weak table entries, including expired entries |
| 72 | Pending open token |
| 80 | Sticky registry poison flag |
| 88 | Last allocated monotonically increasing token |
| 96..111 | Two zero reserved words |

Statuses are 0 success, 1 another open is pending, 2 poisoned registry,
3 absent/nonpublished/dead handle, and 7 storage growth required. Status 7
does not allocate a new identity. Pruning before that storage request remains
the original begin-open operation.

The policy return codes are `0xffffffff` invalid input/state,
`0xfffffffe` insufficient caller storage, and `0xfffffffd` fatal reference
or identity exhaustion. Fatal must not be converted to redacted unavailable or
ordinary cancellation. The MAX_REFS edge follows the original Arc increment
boundary: old count MAX_REFS may become MAX_REFS+1; another increment is fatal.
A new identity never wraps to an earlier token.

The workspace consists of a 128-byte header followed by zero or more 64-byte
cells. Its size is at least 128 and a multiple of 64. Header words are state
magic HRAARW01 at 0, count at 8, serial at 16, poison at 24, pending token at 32,
pending-new flag at 40, and zeros at 48..127. A cell holds token at 0, the four
key words at 8..39, strong count at 40, and zeros at 48..63. Token order is
strictly increasing. Expired cells are compacted only by a later begin.

## Native storage capability

The packed capability is produced by actual HIA code. The independent GNU
assembler extraction is a development reference, not an installed dependency.
The output is a 64-byte header plus PIC code. Header magic is HRARPK01, followed
by total bytes, code bytes, and five offsets in this order: create, apply,
sequence, wait, destroy. The emitter request is HRARPQ01 followed by version 1
and zero, exactly 24 bytes.

The following functions are a closed private C ABI. Call buffers and entry
addresses come from verified runtime bindings, never public request fields.

| Function | Arguments and result |
| --- | --- |
| create | Verified retained HIA entry, initial workspace bytes; returns context or negative errno |
| apply | Context, request pointer, request length, output pointer, output capacity; returns HIA code or negative mechanical errno |
| sequence | Context; returns current unsigned 32-bit wake sequence or negative errno |
| wait | Context, previously observed unsigned 32-bit sequence, relative nanoseconds; returns actual futex result |
| destroy | Context after exclusive outer shutdown and all users joined; returns zero or an explicit refusal |

Create initializes the actual HIA state. Apply serializes real OS threads with
an atomic/futex mutex, captures the input bytes privately, invokes the actual
HIA entry, and copies its complete response under the mutex. Input/output may
overlap one another, but neither may overlap the capability's mutable context
or HIA workspace.

Storage growth is a mechanical consequence of HIA status 7. The engine maps
zeroed storage, copies the complete previous state, releases the old mapping,
then repeats the identical captured bookkeeping request. There is no
application entry limit and no filesystem operation is replayed. This private
dynamic-storage entry is separate from fixed-size convenience QA sessions.
The shared policy image remains immutable and retained over every caller.

The wake counter is not admission authority. A caller obtains the counter
before attempting begin; after status 1 it may wait on that earlier counter.
Completion or poison advances the counter and wakes waiters. EAGAIN means the
counter already changed. EINTR or a timeout does not grant an open reservation.
The caller must still obtain the actual HIA begin result. Waiting does not
replace the public request's original deadline or the AuditStoreLock queue.

The capability is process-bound by the real process ID. Forked children cannot
reuse it. Destroy is nonblocking and refuses a live strong count, an unfinished
open, or a held internal mutex. It also refuses sticky mechanical/fatal errors.
It requires unique outer ownership: all callers and waiters must have ended;
the internal mutex alone is not a proof that an external borrower has returned.
A failed growth cleanup retains both mappings and a sticky error rather than
publishing an unowned allocation. No API permits caller-selected unmapping.

## Qualification boundaries

The policy controls use synthetic trusted identity words and the actual HIA
image. The engine controls additionally execute HIA-emitted machine code,
kernel memory allocation, actual futex waits and 32 OS threads, plus 260
simultaneously live keys. Neither substitutes for the original full dependency
graph's physical Archive/Arc/Weak comparison or for the final public ten
Durable Request handlers.
