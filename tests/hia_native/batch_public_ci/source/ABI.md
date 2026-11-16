# Rebuilt Batch composition ABI

All words below are unsigned little-endian 64-bit values. Offsets are bytes.
All listed reserved words must be zero. Every span is checked before it is
read. This describes a private serial composition; it does not advertise a
public Batch handler or a general async runtime.

## Typed carrier

Input `HBPRQ002` is the existing 24-byte request header: magic at 0, canonical
JSON length at 8, zero at 16, then the complete canonical object. The new
carrier retains the existing owner's full typed parse and diagnostics.

`HBAPRR01` has a 128-byte header. Status at 8 is 0 for success, 1 for an
original typed error, 2 for workspace growth, 3 for output growth, or 4 for a
representational overflow. Operation at 16 is 1; path length is at 24; flags
at 32 are 1; typed content length is at 40. Old/new/replace-all words at
48/56/64 are zero. Diagnostic length is at 72, required capacity at 80, and
88 through 120 are zero. Success contains the decoded path followed by the
complete unchanged `HBPRR002` typed projection. Errors retain its full
diagnostic. This does not reparse unknown fields at a different type boundary.

## Body adapter

The 64-byte `HBBSPQ01` header has operation 1 at 8, context selector 1 or 2 at
16, resolved-path length at 24, complete typed-projection length at 32,
nonzero generation at 40, and zeros at 48/56. Its payload is the resolved path
followed by the complete `HBPRR002` projection. The caller is responsible for
the original public admission, policy, resolution and scope order.

The adapter's child 0 is the actual `batch_plan_input` owner, using
`HBPIQ002` mode 0. Child 1 is the callable body, using `HFBWT001` and returning
`HFBWR001`. Final `HBBSPR01` has a 32-byte header containing operation 1,
success/error kind and the complete message length, followed by that message.

The adapter owns `HBBADS01` workspace state and its `HBBACA01` action at
workspace offset 256. A 112-byte action contains sequence at 8, child at 16,
completed-reply retry at 24, input offset/length at 32/40, output offset and
capacity at 48/56, acknowledgement sequence at 64, child result code at 72,
zeros at 80/88, required completed reply size at 96 and zero at 104.
`0xfffffff0` requests the child call. `0xffffffd0` requests growth through
`HGRWS002`. A complete child reply too large for its loan is delivered as
`0xffffffcd` with its full size; the adapter grows and requests retry 1 for
the same child sequence. The bridge must return the retained reply and must
not repeat a completed filesystem effect. Cancellation uses `0xfffffff7`.

This package builds the adapter. Its dedicated actual multi-child composition
qualification and the public gateway/caller integration remain separate.

## Callable body

The source exports `local_batch_body_run(context, input, length)`,
`local_batch_body_resume(context)`, `local_batch_body_cancel_wait(context)` and
`local_batch_body_release(context)` with the standard x86-64 System V ABI.
The component/build metadata contains the exact assembled symbols and image
identities; callers must use that metadata rather than a stale code offset.

The 192-byte context is `HLBBCI01` at 0, extent 192 at 8, and fourteen-entry
HIA image table pointer at 16. Its remaining fields are:

| Offset | Meaning |
| --- | --- |
| 24 / 32 | Cache callback and opaque argument |
| 40 / 48 | Required hint callback and opaque argument; Batch does not call it |
| 56 | Borrowed 64-byte file-lock state record, actual table member 7 |
| 64 | Borrowed 64-byte history state record, actual table member 3 |
| 72 / 80 | Shared-arena growth callback and opaque argument |
| 88 | Pointer to process-shared statx capability byte, value 0 through 2 |
| 96 | Actual `AT_SECURE` value, 0 or 1 |
| 104 | Zero |
| 112 / 120 | Borrowed complete result pointer and length |
| 128 | Result code |
| 136 / 144 | Publication and drain flags |
| 152 / 160 | Private control pointer and diagnostic code |
| 168–184 | Initially zero |

The exact table order is:

| Member | HIA owner |
| --- | --- |
| 0 | `batch_write` |
| 1 | `file_lock_service` |
| 2 | `file_lock_key` |
| 3 | `history` |
| 4 | Direct `atomic_write` |
| 5 | `view_cache` |
| 6 | Qualified extended `local_read` |
| 7 | `file_lock_state` |
| 8 | `editable_content` |
| 9 | `batch_plan` |
| 10 | `line_endpoint` |
| 11 | `line_verify` |
| 12 | `batch_apply` |
| 13 | `batch_render` |

A borrowed state record contains entry pointer, workspace pointer/capacity,
output pointer/capacity and last result at offsets 0/8/16/24/32/40, followed by
two zero words. Shared growth is
`u32 callback(opaque, actual_table_member, required_workspace, required_output)`.
Only member 3 or 7 may request it. The callback preserves complete live state.
The cache callback is
`u32 callback(opaque, request, request_length, out_span_pointer)`; its result
is the complete variable-size cache reply. The callable copies a Get reply
before making another callback. Scope/session authority must come from the
actual active caller; this ABI does not select an authority.

Completed results are borrowed until `release`. Publication requires both
published and drained to be 1 with diagnostic 0. A returned lock wait is
`0xffffffe1`, retaining a complete 128-byte effect frame and the live control
block with both flags 0. Only that actual returned wait may be resumed or
cancelled; cancellation marks the actual HIA continuation and lets its own
cleanup release the lock state. This does not authorize asynchronous
cancellation of in-flight syscalls or force a Tokio-equivalent scheduler.
Release unmaps only the callable's owned regions. Borrowed history, locks and
the statx capability byte remain owned by the caller/process.

The intended later public slot allocation is gateway 47, params 48, caller
49, adapter 50, input owner 51 and callable 52. Engine offsets 416/424 remain
reserved for that later composition. The current private fixture has no
public engine slot requirement.
