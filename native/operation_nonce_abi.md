# Native operation nonce set

`operation_nonce.hepta` owns the serial set transition from the original
`NonceLedger::reserve`: at most 16,384 successful reservations per scope, with
duplicate detection over `SHA256(operation_id || ledger_identity) || nonce`.
Both identities are the original 64 lowercase hexadecimal ASCII bytes. The
nonce contains exactly 12 arbitrary bytes. Different operation or ledger
identities create different key namespaces; they still share the scope budget.

The source is pinned to runtime commit
`a0dcdda1991ec536d5e2d252c006a778993fa566`, file
`src/mcp/runtime/operation_crypto.rs`, SHA256
`a48463ef35ca41d0aa8ef64fcaeb9d3245773052221789a38d18d52ced891633`.
Eight complete SHA helper functions are imported from the qualified
`binary_codec.hepta` by function-name and call-target relocation only. The
composition proof and native test setup reverse and compare that relocation.

## Scope and custody

This is an internal state component, not a public tool or a nonce generator.
Its workspace must be private, persistent and exclusively owned by one trusted
scope controller. Every clone of a scope must reach that same workspace through
the controller's serialization mechanism. Separate workspaces are separate
scopes and do not share accounting.

The component does not authenticate a bearer, generate entropy, own key bytes,
provide native mutual exclusion, validate arbitrary serialized state, establish
rollback resistance or admit replay after a controller restart. The Python
loader's lock is qualification transport, not a production locking guarantee.
Production activation and complete scope replacement remain separate gates.

Initialization and destruction are trusted lifecycle operations. The controller
must destroy the associated key capability with the ledger; clearing and
reinitializing a ledger under a still-live key would remove its nonce history.
No external caller may request either operation or edit/import its workspace.

## Frame and results

The entry is `(readbuf, mutbuf, mutbuf) -> u32`, with disjoint buffers. Every
request begins with exactly the following 24-byte header. Integers are unsigned
little-endian.

| Offset | Field |
|---|---|
| 0 | Eight bytes `HRNONC01` |
| 8 | Operation number |
| 16 | Reserved u64, exactly zero |

| Operation | Exact request | Behavior |
|---|---|---|
| 1 | Header only | Initialize an entirely zeroed fresh workspace. An active or otherwise nonzero workspace is refused. |
| 2 | Header, operation ID64, ledger ID64, nonce12: 164 bytes total | Reserve the namespace/nonce pair, consuming one unit only if it is new and budget remains. |
| 3 | Header only | Wipe the entire declared workspace, including partially initialized or damaged state. |

Every success returns zero bytes. The output buffer is always unchanged.

| Return | Meaning |
|---|---|
| `0` | Successful lifecycle transition or reservation |
| `0xffffffff` | Invalid header, operation or exact frame length |
| `0xfffffffe` | Workspace smaller than 1,576,960 bytes |
| `0xfffffffd` | Invalid lowercase hexadecimal identity bytes |
| `0xfffffffc` | Duplicate namespace/nonce pair or exhausted original 16,384-use budget |
| `0xfffffffb` | Uninitialized or invalid private state, repeat initialization, invalid probed slot or bounded probe exhaustion |

Admission order is minimum header, magic/reserved/operation, exact frame length,
identity bytes, capacity, then lifecycle/state/budget. A controller must first
apply the original seal admission order: payload limit, complete trusted binding,
entropy, and then nonce reservation. This component validates only the two
identity fields it consumes. Its state refusal is an internal ABI result; it
does not replace the original mutex-poison or complete scope lifecycle owner.

## Workspace and transitions

The used workspace contains 1,576,960 bytes:

| Range | Contents |
|---|---|
| 0..2,047 | Temporary SHA state and the pending 44-byte reservation key |
| 2,048..2,055 | Active-state magic `HNSTATE1` |
| 2,056..2,063 | Successful reservation count |
| 2,064..4,095 | Reserved bytes, zero in valid state |
| 4,096..1,576,959 | 32,768 slots of 48 bytes each |

Each slot has a four-byte occupancy field, either zero or `01 00 00 00`, followed
by the full 44-byte key. Unused slots are zero. The initial probe slot is the
first big-endian u32 of `SHA256(reservation_key)`, masked by 32,767. Linear probing
wraps at the table end and stops after at most 32,768 probes. Equality compares
all 44 bytes; a bucket collision is not a duplicate. The table representation is
private and is not the original Rust HashSet representation or a portable format.

The exact original budget is checked before hashing or probing. A new entry is
committed only after an empty slot is found, and the count advances once. There
is no deletion or retry that refunds a successful reservation. Duplicate or
budget refusal does not change the set or count. The first 2,048 scratch bytes
are zero after initialization and every completed reservation path, including
probe refusal. Under that valid-state invariant, a duplicate leaves the entire
workspace unchanged. Admission/capacity failures leave both mutable buffers
unchanged before any hash work. These guarantees do not authenticate a corrupted
table or count supplied from outside the trusted controller.

Destruction clears every byte of the used region. Initialization, reservation
and destruction leave the workspace tail unchanged. Inputs are never modified.
No constant-time or whole-process memory/register-erasure qualification is made.

## Verification

The native suite compares the complete private set to an independent set model,
checks every successful admission through the full 16,384-use budget, exercises
same-nonce distinct namespaces, arbitrary nonce bytes, duplicate refusal,
collision chains that wrap across slot zero, bounded probe exhaustion, malformed
requests, exact capacities and lifecycle cleanup.

A test-only HIA hexadecimal transport composes a persistent nonce child in a
real syscall-only ELF. Its complete budget and lifecycle trace runs with an
empty `PATH`; Python is only the external test driver. This fixture is not a
production dispatcher. The locked Rust oracle embeds the complete unchanged
original crypto file, constructs actual trusted bindings, and calls the actual
original `NonceLedger::reserve` for the exported stateful traces. Original-owner
execution and aggregate CI must pass before integration is qualified.
