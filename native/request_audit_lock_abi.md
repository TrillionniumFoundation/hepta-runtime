# Native audit store lock

HIA owns FIFO, guard tokens, reader counts, deadlines, cancellation and poison.
The fixed Linux boundary supplies actual clocks, mutex/try-lock, futex, growth
and four real threads. A second HIA module emits the ELF. No Rust, Python, libc
or interpreter is required at runtime. Filesystem callers, public admission,
general language unwinding and production activation remain unqualified.

## Borrowed ABI

Input: exactly 128 bytes, little-endian words. Output: at least 64 bytes.
Shared arena starts at 256 bytes.

| Offset | Input field |
| --- | --- |
| 0 | HRALQ001 |
| 8 /16 /24 | Operation /token /flags |
| 32 /40 | Deadline seconds/nanoseconds, or drop payload |
| 48 /56 | Pre-queue clock |
| 64 /72 | Post-queue or private post-admission clock |
| 80 /88 | Loop clock, refreshed after growth |
| 96 | Physical inner poison, 0/1 |
| 104 | Private deadline-present flag for operations 4/5 |
| 112 /120 | Zero |

Response: HRALR001, operation, status, token, detail, readers, waiting, epoch.
Status: 0 done, 1 wait, 2 grow (extent in detail), 3 turn, 4 try inner, 5 granted,
6 deadline, 7 unavailable, 8 release inner. Normal return is 64. Raw errors are
INVALID=0xffffffff, CAPACITY=0xfffffffe, STATE=0xfffffff9.

| Operation | Meaning |
| --- | --- |
| 0 | Initialize zero arena |
| 1 /2 /3 | Exclusive enqueue /shared enqueue /queued poll |
| 4 /5 | Private post-turn deadline /actual inner try-lock result |
| 6 /7 | Shared finish /dispose after physical inner release |
| 8 /9 | Snapshot /empty shutdown |
| 10 /11 | Trusted poison /notify |
| 12 /13 | Private drop plan /pre-queue deadline |

Operations 4/5/12/13 use private buffers without queue waiting or arena access.
Operation 4 role is 1 exclusive or 2 shared. Operation 5 flag is 0 acquired,
1 poisoned or 2 busy. Operation 7 carries status 0/6/7 at offset 32 and typed
panic in flags. Operation 12 uses offset 32 for its typed 0/1 panic reason.

## Custody and thread boundary

A 256-byte header tracks arena extent, free/queue/live links, next ticket,
exclusive token, readers, three poison bits, live/queued counts and epoch.
Each 96-byte lease stores token=ticket+1, access, phase, deadline and separate
queue/live links. Freed nodes are reused. One physical mutex protects shared
calls, pointer/length changes and growth. First acquisition forces real growth;
pre/post-lock clocks remain fixed while the loop clock advances. No ticket is
reserved until storage exists.

Exclusive entry needs queue head and zero owners/readers; shared entry needs
queue head and no exclusive owner. Adjacent readers may enter together; the
upper archive cohort owns its two-reader limit. Preexpired requests never wait
for queue custody. Deadline/poison ordering, poisoned-wake cancellation and
checked ticket overflow match the original. Physical inner release precedes
FIFO release. Shared finish consumes once under custody; reader underflow
poisons. Later peer poison cannot revoke a finished success.

Qualification commands: 64-byte HRALC001, tag, actor 0..3, command, deadline
mode, duration nanoseconds, two zeros. Modes: 0 absent, 1 relative (at most an
hour), 2 expired. Responses: 80-byte HRALO001, tag, actor, command, status and
five words. Only snapshot command 6 uses next-ticket, poison/active, readers,
waiting; final word is zero. One command may be outstanding per actor.

Commands 1/2 acquire, 3 shared-finish, 4 drop, 5 typed panicking drop, 6 snapshot,
7/8 poison, 9 notify, 10/11/12 actual inner hold/release/panic, 14/15 actual queue
hold/release. Qualification-only 16/17 alter ticket/readers under custody for
overflow/underflow fixtures; they are not public APIs. Workers have guarded
private stacks and actual absolute monotonic futex waits. EOF stops all workers
before joining any, enabling release cascades. Join observes Linux clear-child-
tid; a separate output mutex serializes frames.

## Qualified scope

Fresh Rust 1.95.0, ten unchanged original blocks and two fresh HIA images passed
37 real process pairs /258 application operations per side. Every application
response by tag and every queue milestone matches. Coverage includes FIFO,
four adjacent readers, exclusion, deadlines, poison, spurious wake, failed
try-lock, overflow/underflow, EOF release cascades and actual cleanup/join.
Concurrent arrival order and probe counts are retained but not equated.

Rust poison cases execute real panic unwinding; HIA receives an explicit typed
guard-drop reason, without a general language-unwind claim. Fifty-nine raw and
synthetic-clock controls claim neither original execution nor actual threads.
An earlier local control compared a 256-byte workspace with its allocation
including a 16-byte ctypes canary; the failure and correction remain archived.
