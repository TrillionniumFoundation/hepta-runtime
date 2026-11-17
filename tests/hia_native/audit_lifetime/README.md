# Audit active and read-pin lifetime owner

This is an authoring checkpoint for the HIA replacement of the private ACTIVE
and READ_PINS owners in target d3d75c30719db966b004756f610007a7c723729e.
It is not yet a qualified runtime component or a production caller replacement.

The controller owns key equality, active replacement, append-only pin publication,
weak pruning, strong upgrade, active-first query order and held cohort publication.
The native reference boundary supplies allocation, atomic strong/weak counts,
Acquire observation, Release clearing and final unmapping. The existing qualified
audit synchronization boundary supplies both independent mutexes and poison.
The complete native mechanical pump and actual-thread qualification are pending.

## Original call order

Ordinary read admission creates a strong unit pin, publishes its weak reference,
and keeps the strong pin in RequestTicket through native read completion. Admission
failure drops its own pin. Ordinary and reserved request admission publish a weak
active marker only after the durable record and hot cache steps succeed.

The batch owner creates active markers during preparation. It acquires the active
registry once after durable publication and keeps that one guard across the whole
ready cohort. BEGIN/INSERT/END below preserve that ownership boundary. Publishing
each member through an unrelated lock acquisition would permit observations the
original cohort does not expose.

is_dispatch_active first locks ACTIVE, removes every expired weak reference,
then upgrades only the selected marker and observes its bool with Acquire.
is_active always calls that operation first, then independently locks READ_PINS,
removes all expired pins and empty keys, and returns the OR. A poisoned read-pin
mutex still refuses is_active when the active marker was true. An active poison
is returned before attempting the pin mutex. A false but still strongly owned
active marker remains in ACTIVE until its last strong reference disappears.

## HIA controller ABI

Entry is f0(readbuf request, mutbuf actor, mutbuf current_map) -> u32.
The actor has 512 bytes. Return 512 is a completed controller step; 0xffffffff
is a malformed frame, 0xfffffffe short actor capacity, 0xfffffff9 invalid private
state, and 0xfffffffa unrepresentable resource/sequence extent.

The variable request is HARGQ001 plus seven little-endian u64 words:
operation, nonzero context generation, strong pointer, key byte length,
actual caller panicking flag, private resume sequence, reply length.
The key follows at offset 64, followed by a 128-byte observation area.
A public callable begins with sequence/reply length zero and a zero observation
area. The native pump keeps the original key unchanged through every step.

| Op | Meaning |
| --- | --- |
| 1 | Publish one weak active reference from a live strong marker. |
| 2 | Append one weak read pin from a live unit marker. |
| 3 | Query dispatch activity after pruning all active weak entries. |
| 4 | Query activity, then read pins, using their original error order. |
| 5 | Quiescent final map disposal, including poisoned maps. |
| 6 | Acquire and retain the active registry guard for a cohort. |
| 7 | Insert under the same live cohort guard and actual owner thread. |
| 8 | Release that guard with the actual current unwind observation. |

Only 1, 2 and 7 carry a nonzero owned strong pointer. Operations 5, 6 and 8
carry no key. Keys preserve complete bytes and length; production typed strings
supply UTF-8, including embedded NUL and non-ASCII. No key hash supplies authority.

Actor status selects completion, the existing 128-byte synchronization boundary,
the 64-byte native reference boundary, or map growth. Map bytes are available only
while their actual kernel mutex is held by this call's thread. Shared queries
do not read another map without its mutex. The active and pin maps have independent
custody. Each map is HARMAP01, generation, kind, reserved, count, used extent,
then two zero words; kind is 0 active or 1 read pins. Entries contain key length,
one owned weak pointer, complete key bytes, and zero padding to eight bytes.
Allocation-backed growth has no configured entry-count quota.

A successful query returns result 0 or 1. Publication/disposal/release returns 0.
A held cohort returns 2. Active and read-pin poison return 100 and 101 respectively,
which the actual caller must map to the original distinct errors.

## Native reference ABI

The SysV entry receives a 64-byte request, at least 64 output bytes, and workspace
length zero. Used input/output regions must not overlap. Request words are
HARREF01, operation, kind (1 active / 2 unit), pointer, then four zero words.
New objects have one strong reference plus its one implicit weak reference.

| Op | Meaning |
| --- | --- |
| 0 | Create an active bool initially true; kind 1 and pointer zero. |
| 1 | Create a unit pin; kind 2 and pointer zero. |
| 2 | Clone one independently owned strong reference. |
| 3 | Drop one owned strong reference; final strong drops implicit weak. |
| 4 | Clone one owned weak reference. |
| 5 | Drop one owned weak reference. |
| 6 | Observe the strong count while owning a weak reference. |
| 7 | Upgrade a weak reference only while strong count is nonzero. |
| 8 | Acquire-load an active bool while owning a strong reference. |
| 9 | Release-store false while owning a strong reference. |

Reply words are HARRES01, operation, result, pointer, observed strong count,
observed weak count, kind, observed bool. Upgrade returns result 1 or 0; final
disposal returns 2. Count fields are individually observed atomics, never a
transactionally consistent concurrent snapshot. A release never accesses an
object after its final unmapping. Refcount overflow or allocation failure aborts;
neither is converted to a successful lifetime operation.

Pointers belong to trusted private owners. Forged pointers, stale pointers after
the final owned reference, and data races caused by sharing an exclusively
borrowed actor are outside this ABI. The original Arc interfaces carry the same
valid-reference lifetime requirement. This boundary uses no Rust allocator,
libc, Python callback, dynamic loader or semantic subprocess.

## Source and execution

The source-only workflows verify the pinned target bytes and Hepta commit/tree,
render the HIA controller, atomic emitter and native callable packer, and retain
complete authoring commands and generated bytes. The three test source files
are formatted by Rust 1.95.0 in a separate source-only CI job. Generated bytes
are recovered from the complete job stream and checked against their reported
length, SHA-256 and Git blob identity before qualification.

`DOMAIN.json` fixes 16 paired scenarios, 1,203 native object allocations and
matching disposals, the exact Rust build profile, all 40 process commands and
their original budgets. Each original/native scenario gets a fresh process, so
global `OnceLock` state and poisoning cannot leak across scenarios. The original
four registry functions are included byte for byte. Shared test bodies cover
exact keys, global pruning, active-false strong owners, multiple read pins,
replacement, 513 simultaneous entries, real batch custody, actual unwinding,
16-thread reference contention and 64 last-strong/weak-upgrade races. The race
outcome is retained in full and checked against its allowed nondeterminism;
every deterministic observation must agree with the original.

The optional observer only copies buffers. `observer_free.py` separately makes
43 actual native calls with both observer pointers zero, including 22 fixed
refusals, native map disposal and a strong object that outlives those maps. The
production callable owns its effect loop, atomic references, mappings and lock
operations without a Rust or Python runtime fallback.

`run_gate.py` builds with fresh pinned B1=B2=B3, emits both native images through
HIA, executes the paired scenario processes and seals every complete physical
file. `verify_readonly.py` reads the frozen evidence without execution, native
mapping or protected writes. It validates every effect/reply and actor chain,
actual kernel custody, full map transitions, byte-preserving growth, every
reference balance and final disposal. Twelve physical mutations, two complete
relocations and two post-refusal admissions test the reader under twelve guard
probes each. Refusals retain complete capture bytes and exact error reasons.

Run the gate only in the authorized CI/dev environment. Rust compilation and
semantic execution are not local authoring steps. Ordinary subprocesses remain
bounded at 60 seconds, readers at 180 seconds, builds at 900 seconds, and the
workflow at 15 minutes. A failed or unknown execution remains failed or unknown;
it is not silently retried. Qualification status comes only from the complete
gate and independently reopened evidence. This component does not claim full
request persistence/retention integration, any additional public handler, or
the completed replacement of the whole runtime.
