# HIA audit store effect controller

This source translates the pinned `AuditStoreLock` acquisition and guard lifecycle
into HIA. It yields the exact mutex, condition-wait and monotonic-clock frames of
the separately qualified `audit_native_sync` boundary. Queue admission, deadlines,
FIFO cancellation, reader accounting, shared poison and release order are decided
by HIA. This checkpoint has not yet qualified the composed concurrent controller.

The original owner is the complete, byte-exact excerpt from target commit
`d3d75c30719db966b004756f610007a7c723729e`, path
`src/mcp/runtime/request_audit.rs`. The native synchronization source is pinned to
`0aad43e82c040ce24dfeb1e214ecdf9ac7620356`; its full qualification and independent
readback are retained at `5ba9edacf578639614abee22b377b27250e92933`.

## Custody and order

Shared queue bytes are accessed only during initialization before publication or
while the calling actor owns the actual queue mutex. Actor state remains private
through every unlocked phase. Admitted guards are removed from the waiting queue;
their active flag and deadline live in the actor. An exclusive actor drops the
queue mutex, checks its deadline and uses an actual inner `try_lock`. It introduces
no additional queue lock between admission and that attempt. On failure, ordinary
guard cleanup reacquires the queue mutex. An acquired inner guard is released
before its FIFO reservation is released.

Adjacent readers can join a reader cohort, while a queued writer prevents later
readers from passing it. Shared `finish` checks poison and the deadline while
holding the queue mutex, then decrements the reader count, notifies and releases.
If that first queue lock is poisoned, the error guard is dropped and ordinary
shared-guard cleanup acquires the queue again, matching the original destructor
order. A shared guard dropped while its thread is already unwinding publishes
reader poison. Mutex poison itself is owned by the native synchronization boundary.

## Three-buffer step ABI

The request is exactly 256 bytes. All words are little-endian u64. Its first half
contains `HAUCTL01`, command, continuation serial, boundary return, generation,
deadline-present, deadline low/high, current panic flag, then seven zero words.
Its second half is either zero or the complete actual native boundary response.
Commands are 0 initialize queue before publication, 1 acquire exclusive,
2 acquire shared, 3 resume an emitted effect, 4 finish shared, and 5 drop guard.
Initial commands carry a nonzero synchronization generation. Shared acquisition
requires a deadline. Resume accepts the exact serial and the actual 128-byte
boundary return, or zero for an explicitly completed queue growth.

The output is a private 512-byte actor and continuation. Its header is `HAUCOR01`.
Words 1 through 25 contain status, result, serial, phase, access, deadline-present,
deadline low/high, ticket, actual owner TID, queue-held, inner-held, guard-active,
pending result, panic flag, generation, command, latest clock low/high, pre-lock
clock low/high, sequence, zero, requested queue bytes, and waiting-ticket-active.
Bytes 208–255 and 384–511 are zero. Bytes 256–383 contain the complete next native
`HASCMD01` request when status is 1. Status 0 is complete: result 3 grants a guard,
0 completes initialization/finish/drop, 5 means deadline, and 6 unavailable.
Status 2 requests queue-buffer growth while retaining actual queue custody.
Every successful step returns 512; frame/capacity/state/resource failures retain
their explicit u32 tags. A kernel response outside the frozen mechanical contract
is refused as a state failure; this source does not claim an error-recovery policy
for damaged kernel frames or resource exhaustion.

The shared queue starts with a 128-byte header: `HAUQS001`, next ticket, active
writer, reader count, reader poison, waiting count, used bytes, generation, then
eight zero words. Waiting records are 16 bytes, ticket then access. Admission or
cancellation removes a record and zeros the retired slot. Growth requests the exact
required size and does not change the queue. A mechanical caller must grow it while
the native queue mutex remains held, preserving all existing bytes. There is no
configured waiter or reader count cap.

The continuation serial and native actual TID bind each observed effect to its
actor. The caller must not clone or concurrently access an actor. A mechanical test
pump can pass a zero-length queue buffer whenever it lacks actual queue custody;
the HIA code must complete every unlocked phase without touching shared bytes.

## Current qualification scope

The source author, HIA text, exact original owner and compiler identities are
checkpointed before native compilation or composed execution. The independently
qualified native boundary remains a separate dependency. Original Rust comparison,
actual concurrent-controller qualification, public audit handlers and whole-runtime
replacement remain pending.
