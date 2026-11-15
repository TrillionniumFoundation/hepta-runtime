# Deferred publication of audit activity

This HIA module imports all 21 functions of the frozen activity/read-pin owner
with exact function bodies and call-target relocation. It adds two operations
needed by audit cohort admission: creating an active marker before acquiring
registry custody, and publishing its weak binding after durable admission.
Operations 0–12 delegate to the unchanged base entry.

The existing `HRAAQ001` request, `HRAAR001` result, generation-checked leases,
arena growth, four-worker transport, and custody rules remain in use. The
same unchanged HIA packer and syscall prefix produce the standalone image.
No intermediate host implementation of the new lifetime decisions executes
inside the native process.

## Added operations

| Operation | Input | Successful output |
| --- | --- | --- |
| 13 | Boolean flag at word offset 32; zero token and zero ID length | New strong lease ID and object generation |
| 14 | Nonzero strong lease token at offset 16; UTF-8 ID length at 24 and bytes after the header; zero flag | Value 0 and the existing object generation |

All reserved words remain zero, the maximum ID length remains 256 bytes, and
the standard borrowed-buffer capacity rules apply. Operations 13 and 14 do
not change the framing or introduce a second state allocation.

Operation 13 creates a strong active marker with **no weak registry member**.
Creating and cloning it does not make any ID active. It succeeds even when
ACTIVE is poisoned, because the corresponding original `Arc::new` operation
does not access that mutex. Dropping the final unpublished strong lease frees
the object immediately. The existing private counter exhaustion and growth
outcomes occur before consuming a lease ID or publishing any state.

Operation 14 first checks ACTIVE availability. It then resolves an existing
strong active lease, rejects read-pin leases, and publishes the weak binding.
Replacing a previous marker removes only its old weak binding; outstanding
strong leases remain valid. Repeating publication of the same marker under
the same audit ID is idempotent with respect to reference and registry counts.
An old marker that still has a strong lease may be republished under its same
ID after another marker replaced it.

An activity object belongs to one immutable audit request ID. Its first
publication binds that ID, including a valid empty private test ID. A later
attempt to bind a different ID returns private diagnostic 42 and preserves
the previous binding. Markers created by base operation 1 are already bound
to that operation's ID. This is an admitted audit-ticket identity contract;
it does not claim to expose every aliasing operation that a general Rust
`HashMap<String, Weak<AtomicBool>>` could express. Public callers must preserve
the record ID associated with each ticket.

Registry poison returns diagnostic 38 before private lease validation.
An invalid lease or a read-pin lease returns 40. The existing boolean
store/load, clone, and drop operations remain usable for detached markers and
after a publication error. Failed publication does not drop the caller's
strong lease or convert an uncommitted marker into registry membership.

## State compatibility and batch custody

The base object's unused words at offsets 304 and 312 record whether a
detached object has received its immutable binding, and whether the object
originated as detached. The imported base owner preserves these words during
clone, boolean mutation, registry replacement, pruning, and strong drop;
slot reservation clears them before storage reuse. Publication validates
both tags. All existing offsets, generations, counters, and slot sizes are
unchanged.

Every owner call and arena relocation requires the same custody gate as the
base owner. A future batch coordinator must hold that custody across a cohort
publication group when matching the original multi-insert guard scope. The
standalone qualification transport serializes each command, and this module
does not by itself qualify atomic publication of a complete cohort, its
durable filesystem barriers, or the public batch coordinator.

## Qualification scope

The native suite retains the 36 base scenarios and adds 32 detached/publication
scenarios. These cover unpublished markers, clones, delayed visibility,
republication, replacement of live and expired markers, independent registry
poison, invalid leases, immutable-ID refusal, empty/Unicode/NUL/256-byte private
IDs, geometric arena growth, concurrent publication, and EOF draining of
unpublished leases.

The Rust reference uses the exact six original registry definition/function
blocks and actual `Arc`, `Weak`, `AtomicBool`, and mutex operations. Its
private transport also enforces the immutable audit-ID constraint. Both
transports use a private serialized owner gate. Complete tagged frames are
compared outside commuting allocation/drop groups; every raw frame remains
retained, and those groups compare the complete result multisets and all
subsequent ordered observations.

The base raw-control corpus is retained except that its unknown opcode 13 is
now opcode 15, because 13 and 14 have defined semantics. Additional controls
exercise the new request rules, binding tags, growth preflight, publication
failure, and the synthetic private counter boundary. These controls do not
claim execution of an original allocator exhaustion path.

Native language unwinding, arbitrary unserialized original interleavings,
independent registry-mutex timing, public request dispatch, complete batch
admission, and full audit storage remain unqualified. The module supplies a
required lifetime primitive for those callers.
