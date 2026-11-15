# Audit activity and read-pin lease owner

The HIA owner replaces the data decisions for the audit `ACTIVE` and
`READ_PINS` registries. It owns generation-checked strong leases, weak registry
membership, active boolean values, dead-member pruning, and independent
registry poison. All mutable owner state has one native custody gate. Caller
code holds lease IDs rather than raw pointers into a relocatable arena.

This is a private component. Its current reference harness invokes the exact
original `active_registry`, `read_pins`, `is_dispatch_active`, and `is_active`
functions with real Rust `Arc`, `Weak`, `AtomicBool`, `Mutex`, and `OnceLock`.
Both transports serialize compound commands through their private owner gate.
The comparison does not establish timing equivalence for independently held
original registry mutexes, arbitrary unserialized original interleavings,
native language unwinding, public request dispatch, or complete audit storage.

## Policy requests

The standard three-buffer native entry receives an immutable input, a mutable
output of at least 64 bytes, and private mutable state of at least 256 bytes.
The caller must preserve owner state and must not mutate it between calls.
The input starts with `HRAAQ001` and seven little-endian u64 words.

| Offset | Meaning |
| --- | --- |
| 8 | Operation |
| 16 | Strong lease ID, only for operations 3, 4, 5, and 11 |
| 24 | UTF-8 request ID byte length, only for operations 1, 2, 6, and 7 |
| 32 | Boolean value, only for operations 1 and 5 |
| 40, 48, 56 | Zero reserved words |

The request ID follows the header, with length 0–256 and valid UTF-8. NUL and
noncanonical IDs are valid in this private typed registry interface, matching
Rust string behavior. Public audit ID validation belongs to the caller. No
unused argument may be supplied, and lease-taking operations require a
nonzero ID.

| Operation | Action |
| --- | --- |
| 0 | Initialize an empty owner or inspect an initialized one |
| 1 | Create a strong active marker and replace the ID's weak ACTIVE binding |
| 2 | Create a strong read pin and append one weak marker to the ID's pin group |
| 3 | Clone a strong lease, preserving object identity |
| 4 | Drop exactly one strong lease |
| 5 | Store an active marker's boolean through a strong lease |
| 6 | Execute `is_dispatch_active`, including dead ACTIVE entry pruning |
| 7 | Execute `is_active`, including ACTIVE then READ_PINS pruning/error order |
| 8 | Inspect counts without pruning |
| 9 | Private qualification trigger: mark ACTIVE unavailable |
| 10 | Private qualification trigger: mark READ_PINS unavailable |
| 11 | Load an active marker's boolean through a strong lease |
| 12 | Drop every transport-owned strong lease for shutdown |

Operations 9 and 10 are trusted fault triggers. The Rust reference triggers a
real panic while holding the corresponding original mutex and verifies poison.
The native trigger publishes a typed owner failure; it does not implement or
claim language-level panic unwinding. Existing strong leases can still clone,
store/load, and drop after a registry is poisoned.

## Results and state growth

A completed policy call returns 64 bytes beginning with `HRAAR001` and seven
words: diagnostic, value, object generation, ACTIVE entry count, read-pin key
count, weak read-pin marker count, and strong lease count. Counts include dead
weak members until the original policy would prune them. They are private
qualification observations, not public API fields.

Diagnostic 0 is success. A new or cloned lease returns its ID in value.
Queries and boolean loads return 0 or 1. Successful lease operations return
their object's generation; non-lease operations use generation 0. Diagnostic
38 is the original active-registry error; 39 is the original read-pin-state
error. Diagnostic 40 refuses an invalid private lease or a boolean operation
on a read pin. Diagnostic 41 refuses exhaustion of the private monotonic lease
ID counter. IDs never wrap or get reassigned when physical slots are reused.

Diagnostic 2 requests an enlarged arena, with the required byte length in
value and generation 0. Allocation must occur while the same owner custody
gate remains held. The carrier copies the entire old logical arena into
zero-filled storage, swaps its pointer and length, releases the old mapping,
and retries the identical immutable request. No lease, reference count, or
registry binding is consumed before a growth result. The initial logical
arena is 256 bytes; the first two-slot publication requires 1,280 bytes.
Subsequent capacity grows geometrically, rounded to system pages, with a
guard page after each physical mapping. Memory/resource failure terminates
the private carrier instead of fabricating a successful publication.

Malformed input returns `0xffffffff`, insufficient output or minimum state
capacity returns `0xfffffffe`, and rejected private state layout returns
`0xfffffff9`. These raw return codes are not completed 64-byte responses.
The qualification loader checks borrowed-input immutability and buffer
canaries. The production carrier accepts only its admitted typed command
domain; raw rejection controls are tested separately through the loader.

The state header occupies 256 bytes and each slot occupies 512 bytes. A slot
is free, an active marker object, a read-pin object, or a strong lease. Object
slots retain their generation, strong count, weak membership, boolean, and
ID bytes. Lease slots bind both an object offset and generation. Offsets are
validated before use. Objects are recycled only after both strong leases and
registry weak membership have ended.

## Required behavior

ACTIVE replacement removes only the old weak binding. Existing strong leases
to the old marker continue to refer to that marker and cannot change the new
binding. Cloning a read pin extends its lifetime without adding another weak
marker. Creating another pin adds a separate marker to the same group.

`is_dispatch_active` first checks ACTIVE availability, prunes all dead ACTIVE
entries, and reads the selected marker's boolean. An inactive boolean with a
live strong owner remains a registry member. `is_active` executes that full
step before checking READ_PINS, prunes dead pin markers and empty groups, and
returns the dispatch snapshot or presence of a live pin group. READ_PINS is
still checked when the dispatch snapshot is already true. ACTIVE failure
therefore precedes READ_PINS failure, and ACTIVE cleanup may remain observable
when the later READ_PINS access fails. A read pin never converts an unknown
dispatch into an accepted dispatch.

All native lease and boolean operations execute under the same physical
atomic/futex gate. Its acquire/release ordering is stronger than the original
individual atomic boolean operations. Independent original mutex timing and
arbitrary unsynchronized foreign references are outside this qualified
interface; public integration must route every lease/boolean operation through
the owner.

## Four-worker process transport

The standalone Linux x86-64 image has no Rust, Python, libc, interpreter, or
external executable dependency. The HIA packer emits the fixed syscall,
thread, framing, and owner-gate boundary. All lifetime and registry decisions
remain in the HIA policy image.

A command is 384 bytes: `HRAAC001`, tag, actor 0–3, request byte length,
four zero words, then up to 320 bytes of policy request and zero padding.
There is at most one outstanding command per actor. A response is 96 bytes:
`HRAAO001`, the same tag and actor, policy result length 64, and the complete
policy result. Tags bind responses even when independent workers complete in
a different order.

Workers use actual Linux clone threads, guarded 2 MiB stacks, futex custody,
and `CHILD_CLEARTID` joins. EOF first requests that all workers stop, drains
already submitted commands, joins all four workers, then drops all strong
leases and verifies the empty strong-lease set before process exit. State
arena relocation occurs under the same custody gate as every policy call;
no raw arena pointer escapes to another worker between calls.

Serial cases compare complete tagged result bytes against the original.
Concurrent read cases also compare complete tagged frames. Concurrent clone,
drop, and pin-publication cases preserve every raw frame while comparing the
result multisets for commuting operations and all subsequent ordered results.
This accommodates scheduler-dependent assignment of fresh private lease IDs
without treating different observable registry states as equivalent.
