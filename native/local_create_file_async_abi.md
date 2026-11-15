# Segmented private local Create ABI

The existing `local_create_file.hepta` owns both entries. Its original sixteen
functions and `HLCREQ01` behavior remain intact. The first entry dispatches the
additional `HLCARQ01` protocol to an async controller which delegates every
open, partial write, EINTR retry, WriteZero decision and ordinary close result
to those existing functions. There is one write policy.

This ABI describes the controlled Linux x86-64 local leaf. Full
`create_file_spec`, parent directory creation, canonical cache keys, public MCP
routing, runtime shutdown and arbitrary Tokio scheduler configurations have
separate callers and qualification. The process bridge drains and reaps its
owned worker before retiring the backing storage.

## Borrowed request and response

The request is 64 bytes followed by exact path and content bytes. All words
are little-endian u64. The fields are magic `HLCARQ01`, operation, path length,
content length, nonzero generation, ticket sequence, reserved zero, and the
parent's cancellation observation (0 or 1). The sequence is zero for
initialize, poll, cancel and poll continuation; other operations require the
current HIA-issued ticket sequence. The worker operation cannot set cancel.

| Operation | Meaning |
| --- | --- |
| 1 | Initialize a private controller and retain immutable request bytes |
| 2 | Begin a poll turn |
| 3 | Acknowledge successful actual worker admission |
| 4 | Continue the admitted worker, including typed syscall completion |
| 5 | Complete one parent-owned inline close |
| 6 | Observe cancellation at the applicable poll boundary |
| 7 | Acknowledge actual worker termination and reap |
| 8 | Continue the current poll turn |

The output needs 128 bytes. Invalid input returns `0xffffffff`; insufficient
borrowed capacity returns `0xfffffffe`. Both preserve complete output and
workspace arrays. Ordinary completion uses the original 48-byte `HLCRER01`.
Control output is 128 bytes, with magic `HLCASR01` and extent 128.

| Byte offset | Field |
| --- | --- |
| 16 | Action |
| 24 | Life state |
| 32 | Generation |
| 40 | Current worker ticket sequence |
| 48 | Bytes accepted by successfully admitted write tickets |
| 56 | Bytes actually completed by writes |
| 64, 72 | Retained ordinary result kind and errno |
| 80, 88 | Ticket start and immutable ticket end |
| 96 | Original core phase |
| 104 | Opaque descriptor token |
| 112 | Cleanup bit, reaped bit, ticket status, parent phase, cancel bit |
| 120 | Reserved zero |

Flags use bits 0 and 1 for cleanup and reap, bits 8..15 for ticket status,
bits 16..23 for parent phase, and bit 24 for deferred cancellation. Life values
are runnable=1, polling=2, waiting=3, dropped=4, done=5, and dropped/drained=6.
Ticket status is none=0, prepared=1, queued=2, running=3, ready=4.

Actions are queue-open=1, queue-write=2, wait=3, inline-close=4, cancelled=6,
drain=7, worker-syscall=8, worker-ready=9, continue=10, and reap=11. A prepared
effect is not a queued worker, and a returned syscall is not a published
worker-ready result. These distinctions control cancellation and FD custody.

## Workspace and ticket custody

The original core extent is `C = 513 + path_length + content_length`. Async
metadata begins at `A = align8(C)` and occupies 256 bytes. Original reserved
words remain unchanged. Bytes after `A + 256` are caller-owned tail bytes and
are preserved. Every resume validates generation, frame extents, immutable
path/content, metadata relations and the applicable original core state
before mutation.

OPEN runs inside one admitted worker, including the NUL-path check and open
EINTR retries. It stops when the first WRITE or empty-body CLOSE is prepared.
A WRITE ticket freezes the old chunk end before calling the original resume
function: the original function may prepare the next chunk, but the current
worker cannot dispatch it. The chunk maximum remains 2 MiB.

Cancellation during a running ticket lets that ticket finish its complete
write-all retry loop, then closes its descriptor once. A ready result with no
in-flight I/O is closed inline before cancellation is published. An active
poll cannot be split between ready consumption and next admission, or between
the final flush completion, close and ordinary Ready result.

The core effect sequence counts prepared effects. Cancellation may replace
one prepared, unqueued WRITE with CLOSE. The bridge permits precisely that
one skipped sequence only for a dropped controller's inline/orphan CLOSE;
other effects retain the original consecutive rule. Descriptor tokens bind
to an actual owned descriptor, including FD 0. Close retires custody before
the syscall and never retries an EINTR result.

## Static process bridge

The one-shot bridge reads an outer u64 frame length and an initialize request.
External initial frames cannot issue private resume, queue, cancel or reap
commands. Normal stdout is u64(48) plus `HLCRER01`. Cancellation stdout is
u64(128) plus the actual `HLCASR01` cancellation observation. The process still
drains and reaps any admitted worker before successful process exit.

Stderr retains complete 96-byte `HLCREF01` syscall records and 128-byte
`HLCASR01` observations. Individual records are atomic on a pipe; concurrent
parent/worker observation records are not a total order of HIA calls.

SIGUSR1 requests cancellation through a separate mechanical bit. SIGUSR2
coalesces a mechanical wake request at shared-control offset 120 and wakes
the existing futex. Only a previously returned WAIT boundary consumes this
bit and invokes the existing poll operation. It does not set ready, accepted
bytes, ticket state or cancel, and introduces no new await boundary.

The bridge owns one child ticket at a time, shared FD custody, the HIA-call
mutex, immutable request mappings, actual wait/reap, parent-death cleanup and
backing retirement. Worker/bridge infrastructure failures remain failures.
The complete original blocking, segmented typed, actual filesystem, initial
admission and independently controlled Tokio held-event evidence are retained
under distinct qualification records.
