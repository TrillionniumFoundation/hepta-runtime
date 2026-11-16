# Native audit synchronization boundary

This source supplies the mechanical Linux x86-64 operations needed by the HIA
audit controller. The existing HIA queue owns admission, deadlines, cancellation,
reader custody and FIFO policy. This boundary owns only the two kernel mutexes,
condition sequence, actual thread identity, panic-transition poison flags and
monotonic clock observation. A concurrent HIA audit controller is not yet qualified.

The HIA emitter contains 1,635 position-independent instruction bytes authored
from `authoring/audit_sync_adapter.S`. There are no relocations or undefined
symbols. The emitted code uses no libc, dynamic loader, Python, Rust owner or
child process. GNU binutils are authoring tools. The Rust file is an independent
test process which maps and calls the bytes actually emitted by compiled HIA.

## Boundary ABI

The SysV AMD64 entry takes `(input, input_length, output, output_capacity,
state, state_capacity)` and returns a `u32`. The input is exactly 128 bytes, the
output uses 128 bytes, and the shared state uses 64 bytes aligned to eight bytes.
Used borrowed regions must not overlap. Bytes outside the used output and state
ranges remain unchanged. Invalid input returns `0xffffffff`, short capacity
`0xfffffffe`, and invalid state or custody `0xfffffff9` without buffer writes.

All words are little-endian. Input words are magic `HASCMD01`, operation,
mutex kind (0 queue, 1 inner), nonzero generation, expected condition sequence,
actual observed `thread::panicking` flag, relative-timeout-present flag, seconds,
nanoseconds, then seven zero words. Operation 0 initializes zero state; 1 locks;
2 tries to lock; 3 unlocks; 4 releases/waits/reacquires the queue mutex; 5 notifies
all condition waiters while holding the queue; 6 observes CLOCK_MONOTONIC; 7
reads individual atomic status fields. Only lock/try/unlock accept a panic flag.
Only wait accepts a sequence and optional timespec. Seconds must fit signed
64 bits and nanoseconds must be below one billion.

Output words are magic `HASYNR01`, operation, result kind, actual kernel TID,
wait/kernel errno, condition sequence, queue poison, inner poison, monotonic
nanoseconds low/high, generation, queue owner, inner owner, queue-held,
inner-held, and zero. Result kinds are 0 clean, 1 acquired with poison, 2 would
block, or 6 kernel failure. A condition wait reacquires queue custody before
returning; timeout, interruption and changed sequence are observations for the
HIA deadline/admission policy. Status fields read without the mutex are individual
atomic observations, not a transactionally consistent global snapshot.

State layout is magic `HASYNC01`; queue lock/poison u32 at offsets 8/12;
inner lock/poison at 16/20; condition sequence/reserved u32 at 24/28;
queue/inner owner TID u64 at 32/40; generation u64 at 48; and panic-at-acquisition
u32 flags at 56/60. Poison is published only when a guard entered outside an
unwind and leaves during that unwind. Condition waits preserve the original
acquisition flag. Only the actual kernel owner may release a mutex.

The frozen qualification domain includes fifteen real-thread tests, with
16 contending writers and 65 condition waiters, actual owner unwinding, entry
during an existing unwind, poisoned reacquisition, zero timeout, notification
races, signal interruption, independent mutexes, actual clock bounds, generation/canonical frame
refusals, capacity refusals, overlapping buffers and corrupted control words.
Every actual call retains the complete request and physical output before/after;
quiescent checkpoints retain the complete state plus sentinel tail. Shared live
atomic state is never mislabelled as a frozen whole-memory snapshot.

Source checkpoint only: HIA emission and real-thread qualification must complete
before this component is admitted. Whole-runtime replacement, full audit-owner
replacement, public audit and production activation remain false.
