# HIA audit store effect controller

This source translates the pinned `AuditStoreLock` acquisition and guard lifecycle
into HIA. It yields the exact mutex, condition-wait and monotonic-clock frames of
the separately qualified `audit_native_sync` boundary. Queue admission, deadlines,
FIFO cancellation, reader accounting, shared poison and release order are decided
by HIA. The complete composed gate below must pass before this package can claim qualification.

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
The three borrowed regions must be disjoint. Initial commands carry a nonzero synchronization generation. Shared acquisition
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

## Frozen composed qualification domain

The complete source, test domain, recipes and inert readers are frozen before the
fresh composed run. `build.py` compiles the controller and the already qualified
boundary emitter from a fresh pinned B1=B2=B3. The emitted OS instructions run in
the same actual Rust-hosted process as the controller. The host maps immutable code,
executes the exact emitted effect, grows a buffer under retained custody, and
records bytes; it implements no queue admission or deadline policy.

Both the unchanged original owner and the native adapter compile the same five
original tests plus four actual-thread cases: 16 exclusive workers each performing
16 protected increments, 65 simultaneously held shared guards, an exclusive owner
unwinding, and acquisition during an already active unwind. The native adapter also
brackets 128 exact Instant mappings with independent actual kernel clocks. The
source-owned domain requires 13 contexts, 399 actors and 774 completed API commands.
Native scheduling, repeated observations and wakeups are retained in full; their
counts are not replaced with a precomputed transcript.

`read_capture.py` reads every source, compiler input/output/tail, journal record,
actual effect, actor state, shared queue transition, quiescent kernel state and
process stream. It performs no HIA or Rust execution. Ten physical mutations must
be rejected for their intended semantic reasons after full envelope rebinding.
Two complete relocations and two post-refusal admissions each retain a fresh
12-probe no-execution/no-write guard proof. Original 60/180/900-second process
budgets and a 15-minute CI job limit remain fixed.

A successful gate qualifies this frozen actual controller domain. Public audit
handlers, resource exhaustion recovery and whole-runtime replacement require
separate closure and are not implied by this package.
