# Ordinary local `view` read boundary

This owner is being integrated into the ordinary local regular-file branch of
`view`. It owns actual path-following metadata, strict UTF-8 reads and separate raw byte reads to EOF.
It does not introduce the atomic-reader policy's no-follow, single-link,
identity-freeze or 64 KiB total-read restrictions. The caller retains the
original 5 MiB metadata checks and the two independent reads for a range.

The first static executable is a component fixture. It is not an MCP route.
Production dispatch, typed parameters, installed path policy, session identity,
cache lifetime, canonical cache keys and response publication are separate
pinned children of the `view_call` controller. No whole-view or runtime closure
is claimed by this component.

## Private requests and retained snapshots

The entry is `f0(readbuf, mutbuf, mutbuf) -> u32`. Words are little-endian u64.
The 64-byte request is `HVRDQ001`, operation, generation, path length, and four
zero reserved words, followed by the exact Unix path bytes.

| Operation | Fields and lifetime |
| --- | --- |
| 1 | Begin path-following metadata; generation zero and path bytes present. |
| 2 | Begin strict UTF-8 read to EOF; generation zero and path bytes present. |
| 3 | Cancel the current private generation; no path bytes. |
| 4 | Drop a terminal generation and its owned snapshot; no path bytes. |

A separate 64-byte `HVRDB001` frame accepts only operation 5, a raw read to
EOF, with the same generation/path/reserved layout. It performs the same
actual open/read/close and retains every byte, including invalid UTF-8 and
NUL content. The old `HVRDQ001` magic continues to reject operation 5; the raw
magic rejects operations 1 through 4. Cancellation and drop use the original
operation 3/4 frames with the private active generation. This separation
preserves all original strict-read admission and failure behavior.

Raw reads do not perform UTF-8 validation. The literal-search HIA caller
converts the complete successful snapshot with the original lossy UTF-8
semantics after EOF; a read error cannot be replaced by a decoding result.

A begin frame remains immutable until terminal completion. Re-invoking that
same frame advances only an admitted completion or returns the existing pending
effect/result. It does not repeat a completed read. A new begin is accepted only
after the prior object is dropped. Each new object gets a monotonically
increasing private generation; effect sequences also never repeat. These values
are dispatcher bookkeeping, not public request IDs or authorization tokens.

The fixed 80-byte result is `HVRDR001`, generation, original operation, outcome,
errno, mode, metadata size, snapshot offset, snapshot length, and completed read
attempt count. Outcomes are 0 success, 1 OS error, 2 embedded-NUL path, 3 invalid
UTF-8, 4 cancelled, and 5 dropped. Only successful operations 2 and 5 expose a snapshot
span. It remains immutable in the private workspace until drop. The trusted
caller borrows that span; no pointer is retained across allocation or relocation.

Metadata uses a normal following `newfstatat(AT_FDCWD, path, ..., 0)`. Read uses
`openat(AT_FDCWD, path, O_RDONLY | O_CLOEXEC)`, ordinary reads to EOF and one close
attempt. Hard links and symlinks are allowed. EINTR retries a read with a new
sequence. Invalid UTF-8 is remembered across chunks, but does not stop the read
before EOF; a later I/O error remains the read error. Embedded NUL is reported
without calling the kernel. Error text and source-display prefixes are formed
by the caller from these typed outcomes.

## Closed effects and growth

The 128-byte private effect at workspace offset 512 contains `HVRDFX01`,
sequence, generation, kind, four arguments, completion sequence, completion
generation, result, errno, auxiliary mode, auxiliary size, and two zero words.
Kinds are 1 metadata, 2 open, 3 read, and 4 close. No raw descriptor is accepted
from an ordinary request. The boundary owns exactly one private file slot.

Metadata/open use the complete copied, NUL-terminated path at offset 4096.
Metadata writes a private Linux stat buffer at offset 1024. Read names slot 0,
an exact append offset in the owned arena, and 65,536 bytes. That count is an I/O
window, never a total input limit. Close retires slot 0 before its single syscall
attempt; EINTR does not cause a descriptor to be closed twice. The boundary
validates every kind, phase, span, slot, generation and sequence before a syscall.

The owner returns `0xfffffff0` for a pending effect, `0xffffffef` for cancellation
waiting on an already issued effect, and `0xffffffd0` for allocation growth.
The growth record at offset 640 is `HVRDG001`, a monotonic growth sequence and the
required extent. Growth preserves the complete private arena and happens only
between HIA invocations. Source/output mappings are disjoint from that arena.
All offsets and accumulated byte counts are checked before addition. There is
no fixed cumulative byte or chunk-count quota. LP64 representation, available
memory and actual kernel I/O remain real resource limits.

Malformed frame, stale generation or malformed completion returns
`0xffffffff`; insufficient borrowed output/header capacity returns
`0xfffffffe`. These refusals preserve the output and retained state. A failed
allocation is a native resource failure, not a synthetic original tool error.

Cancellation does not release a workspace or descriptor while a syscall may
still complete. It marks the object cancelled. A late admitted open completion
can only install the slot long enough to close it; a late read cannot reactivate
the result. Terminal cancellation requires the slot to be retired. Fatal adapter
exit independently closes any live slot. The request-scope owner holds the
continuation's resource lifetime and keeps its hint/cache capability inactive.

## Caller order

The real local regular-file controller keeps the original order: typed params;
first-capabilities workdir update; current-workdir snapshot; installed path
policy; request scope; original exists/directory dispatch; endpoint parsing;
optional first metadata/read; second exists/file/metadata/read; canonical key;
prior cache snapshot; prepare; commit the cache action; render and the 8 MiB base
gate; drain hints; seal and publish; close scope. Metadata and read observations
are separate. Cancellation or an error after cache application does not roll
that application back.

The caller uses `HVIEWR01` offset 104 to separate the base from appended range
hints. It publishes the base and the request scope's drained hints once. A
semantic rendering error does not append hints. Direct renderer tests and a
manually driven I/O fixture are not counted as production dispatcher execution.
