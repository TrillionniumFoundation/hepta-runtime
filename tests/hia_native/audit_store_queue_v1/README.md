# HIA audit-store queue owner

The target is the exact `AuditStoreLock`, `AuditStoreQueue`, writer guard and
shared guard in runtime commit `d3d75c30719db966b004756f610007a7c723729e`.
This component owns the serialized queue and guard policy. A surrounding native
controller must own the actual mutex, condition variable, clock observations and
thread lifecycle. It must release the writer's actual inner mutex before releasing
the FIFO reservation. The component is not yet a concurrent native lock or a
public audit tool.

The original code has no reader-count limit. Adjacent readers can share a turn;
they cannot pass an earlier queued writer. A deadline that expires after admission
does not end an already held reader's custody: finish or drop must run. Reader
panic poison and the original inner/queue mutex poison are retained separately.
Shared finish is its success boundary; poison published afterward cannot revoke
an already completed result.

## Borrowed-buffer ABI

The entry has the standard `readbuf, mutbuf, mutbuf -> u32` signature. The input
is exactly 128 bytes, sixteen little-endian words. The first word is `HAUDLK01`.
The remaining words are operation, original zero-based ticket, access (exclusive
0/shared 1), deadline-present, deadline low/high, first clock low/high, second
clock low/high, mechanical observation, owning thread token, then three zeros.
Clock values are unsigned 128-bit nanoseconds relative to one retained monotonic
epoch. Begin receives the actual pre-queue and post-queue clock observations.
Subsequent clock-bearing phases receive the actual observation at that phase.
The private thread token must bind to the actual acquiring thread; this owner
does not create that external identity.

| Operation | Meaning | Result/action |
|---|---|---|
| 0 | Initialize an empty owned workspace | Empty state |
| 1 | Enqueue after pre/post queue admission | Queued or deadline/unavailable |
| 2 | Observe loop clock and clean/poisoned wait outcome | Wait, admitted, or cancelled |
| 3 | Observe post-admission clock | Shared held, writer try-inner, or release |
| 4 | Observe actual writer try-lock result and success clock | Writer held or release |
| 5 | Finish a held shared guard under the actual queue lock | Success/deadline/unavailable, then release |
| 6 | Drop an admitted/held guard on its owning thread | Publish panic poison if applicable, then release |
| 7 | Record actual queue/inner mutex poison | Persistent poison observation |
| 8 | Observe current private queue state | No mutation |
| 9 | Retire an empty fixture workspace | No live custody permitted |

The 128-byte response starts `HAUDLR01`, followed by operation, result, ticket,
phase, notify-all count, next ticket, active writer, reader count, reader poison,
queue poison, inner poison, waiting count, live guard/waiter count, used bytes and
effect flags. Results are 0 success, 1 queued/waiting, 2 admitted reservation,
3 held guard, 4 try the actual inner mutex, 5 deadline, 6 unavailable. Effect bit
0 requires dropping an actual inner guard before publishing FIFO release. The
enclosing controller must perform that order while it owns serialization; a
response is not evidence that a system effect already occurred.

Observation is 0/1 clean/poisoned wake for poll; 0/1/2 acquired/poisoned/would-block
for the actual inner try-lock; 0/1 normal/panicking for drop; and 1/2 queue/inner
for poison publication. Unused fields must be zero. A waiter first polls directly
after enqueue; a WAIT result may then enter the actual condition variable.

Workspace state has a 128-byte header followed by 80-byte live entries. Entries
retain ticket, access, phase, deadline-present, 128-bit deadline and acquiring
thread token. Tickets remain ordered; retiring a record compacts the full live
tail and zeros the retired range. Phase 1 is queued, 2 admitted, 3 awaiting the
writer's actual inner try-lock, and 4 held. The header retains next ticket, active
writer, reader count, all three poison bits, live count, used extent and writer
ticket. Complete canonical state validation precedes mutation. A forged or
malformed workspace is a private ABI refusal, not an original application result.

Workspace growth uses the existing `HGRWS002` response with kind 1 and exact
required capacity; the owner does not change any workspace byte on growth. There
is no fixed policy cap on readers or queued callers. Physical machine resources
and the enclosing declared buffer profile remain explicit limits. Original
checked ticket exhaustion is reported as unavailable.

`authoring/` is a source renderer. The executable implementation is generated HIA;
Python is not part of its production path. Original Rust is retained solely as
the immutable reference until full replacement qualification has closed.


## Complete native capture and limited original comparison

The v2 qualification recipe retains every v1 HIA function, every one of the
70 frozen model scenarios (1,933 semantic calls), all 68 private refusals and
the exact initial capacities. The manifest adds the complete evidence reader,
original observers and process custody; it does not widen the runtime claim.

The unchanged 7,395-byte target lock is compiled with Rust 1.95.0 and the exact
target development profile. The unchanged 8,045-byte test excerpt runs all five
original concurrency tests. A separate observer executes the original lock
with six reader cohorts of 1, 2, 3, 32, 65 and 257 and a queued writer / reader /
writer / reader schedule. Its 748 complete observable queue snapshots are
compared byte for byte with the corresponding actual HIA output and state,
using a selector frozen before any new execution.

This is a limited original comparison. Intermediate clock / mutex events and
all other private boundaries remain explicit model cases. The HIA component
still requires a native mutex / condvar controller that binds actual thread
ownership and performs the emitted inner-unlock effect before publishing
queue release. Passing this recipe does not qualify that controller, the public
request audit handler, or the whole runtime.

The fixed reader consumes every actual call's input, full output before/after,
and full workspace before/after. It checks complete growth transfer, unused
buffer tails, private refusal immutability, compiler output, retained compiler
sources, exact source excerpts, actual process commands/PIDs/PGIDs/budgets,
original test output and original trace bytes. Sixteen frozen evidence
mutations exercise deeper readers with repaired file/stream envelopes where
appropriate. Two complete relocated copies are admitted before and after the
refusals. All 20 guard proofs retain full before/after byte and filesystem
metadata inventories and all 12 execution/write refusal probes.

Native and reader processes retain the existing 180-second limits; Rust version
inspection uses 60 seconds and reference compilation uses 900 seconds. The CI
job retains its 15-minute outer limit. Failed processes are killed and reaped
before evidence writes. Complete success or failure is archived with all source
and retained physical evidence. No Rust or HIA runs during archive reading.
