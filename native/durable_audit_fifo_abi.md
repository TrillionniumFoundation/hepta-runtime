# Durable audit FIFO owner, private ABI 1

This HIA component owns the original writer/reader admission queue, ticket
allocation, reservations, poisoning, deadlines, and release transitions.
The installed broker must serialize calls with the same actual audit queue
mutex, supply its actual monotonic clock and lock outcomes, and retain the
actual inner/file I/O guard until the corresponding transition. Private frames
are not public MCP parameters. The Rust fixture in scripts is qualification
only: it provides real Mutex/Condvar/Instant and maps native decisions, without
a replacement Rust admission policy.

The 64-byte input is `HRAFL001`, followed by operation, monotonic now,
deadline-present, deadline, ticket, outcome flags, zero reserved word.
Flags are bit 0 queue poisoned, bit 1 inner mutex poisoned, bit 2 actual
try-lock WouldBlock, bit 3 current thread panicking.

Operations:

| Op | Meaning |
| --- | --- |
| 0 | Initialize a zero workspace |
| 1 | Enqueue a writer; optional deadline |
| 2 | Enqueue a reader; deadline required |
| 3 | Poll this exact FIFO ticket |
| 4 | Check time after reservation; request writer inner-lock attempt |
| 5 | Report actual writer inner-lock attempt |
| 6 | Drop writer, after the actual inner guard has dropped |
| 7 | Finish reader while holding the final queue snapshot lock |
| 8 | Drop reader; panic poisons the store |
| 9 | Cancel a waiter after an actual poisoned Condvar wait |
| 10 | Deadline preflight before acquiring queue mutex |

Output is 64 bytes, `HRAFO001`, status, ticket, required workspace, notify,
then three zero words. Status: 0 finished, 1 queued, 2 reserved, 3 held,
4 deadline, 5 unavailable, 7 grow workspace, 8 perform actual inner try-lock.
Malformed input/state returns `0xffffffff` with no mutation; short output
returns `0xfffffffe`.

Workspace is `HRQST001`, next ticket, writer-active, writer ticket,
reader count, reader-poisoned, live entry count, then 72 zero bytes.
Each 64-byte entry is ticket, access (1 writer / 2 reader), phase
(1 waiting / 2 reserved / 3 held / 4 writer-inner-pending), deadline-present,
deadline, and three zero words. Every call validates the full state, ticket
ordering/uniqueness, reservations, and reader/writer exclusion.

There is no application queue cap. Grow is a read-only result, consumes no
ticket, and permits the broker to grow its owned workspace before submitting
the same admission. Ticket overflow refuses. A deadline does not autonomously
release a held reservation or a running blocking operation. Writer failure
retains the reservation until actual inner guard drop plus operation 6; a
reader requires finish/drop. Finished reads are not retroactively poisoned.

Qualification preserves all nine complete original multithreaded method
bodies and their budgets, including 32 parallel readers and queued writers.
Twenty-six additional actual HIA controls exercise malformed states, forged
tickets, release replay, expiration, exact grow, and capacity boundaries.
