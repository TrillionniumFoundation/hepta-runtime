# Native HistoryStore owner

`history.hepta` implements the serial state transitions of the original
`HistoryStore` from runtime commit
`a0dcdda1991ec536d5e2d252c006a778993fa566`. Its source SHA256 is
`e00f11f708239c1c8b4ee06da7833433ef86427ebd77544fc9b46ce2b6eb44eb`.
The source contains 12 HIA functions. Four UTF-8 and integer helpers are copied
from the pinned text-budget owner with their complete call graphs unchanged;
qualification reverses the declared relocation and compares every operation.

The module owns per-key snapshots, the stale eviction-event queue, byte totals,
latest-snapshot removal, explicit instance lifetime and serial poison outcomes.
Path authorization, canonical keys, shared mutex scheduling, file reads,
atomic writes, write-failure ordering, and production tool routing remain
separate owners. This component does not qualify the complete undo tool.

## Request and response

The borrowed-bytes native ABI takes immutable input, mutable output, and an
instance-owned mutable workspace. All integers in the binary frame are unsigned
64-bit little-endian words. Input consists of this 64-byte header followed by
the exact key and value bytes:

| Offset | Field |
| --- | --- |
| 0 | Eight-byte magic `HHISTQ01` |
| 8 | Operation |
| 16 | Total-byte eviction threshold, only for push |
| 24 | Key byte length |
| 32 | Value byte length |
| 40, 48, 56 | Reserved zero words |
| 64 | Key bytes, followed immediately by value bytes |

Both key and value must be valid UTF-8. Embedded NUL, CRLF, empty keys and empty
values retain their exact bytes. The owner performs no normalization. Every
declared length must account for the complete input; trailing bytes refuse.

| Operation | Meaning | Additional fields |
| --- | --- | --- |
| 0 | Initialize a fresh private instance | No key, value or threshold |
| 1 | Push a snapshot and apply original eviction | Key, value, threshold |
| 2 | Pop the latest snapshot for the key | Key only |
| 3 | Inject a serial poison observation for qualification | No key, value or threshold |
| 4 | Destroy the instance and erase its used state | No key, value or threshold |

The output header also occupies 64 bytes: `HHISTR01`, result kind, payload
length, total snapshot bytes, snapshot count, queued-event count, poison flag,
and a reserved zero word. A successful pop appends the exact snapshot bytes.
Result kinds are `0` for a unit result, `1` for a found snapshot, `2` for a
missing snapshot, and `3` for a poisoned instance. A found empty snapshot has
kind `1` and zero payload bytes, and remains distinct from a missing snapshot.

The native return value is the complete output length. `0xffffffff` refuses an
invalid frame, `0xfffffffe` refuses capacity, and `0xfffffffd` refuses corrupted
or invalid state. These refusals leave both output and workspace unchanged.
The caller's input and the output/workspace guard bytes are checked by the
native loader. A poisoned instance accepts lifecycle operations but refuses
ordinary push/pop with the original poison outcome.

## Exact original transition rules

Each key retains at most ten snapshots. A push drops that key's oldest snapshot
when it already has ten, appends the new snapshot, and appends a key event to
the global queue. If the total snapshot byte count exceeds the supplied
threshold, events are removed from the front while more than one event remains.
An event removes the oldest currently retained snapshot for that key if one
exists. Missing keys are skipped.

A pop removes the newest snapshot and updates byte totals, but deliberately
does not remove old events. Consequently, an old event can later evict a newer
snapshot pushed under the same key. The implementation preserves this behavior.
It also preserves a single snapshot larger than the threshold when only one
queue event remains. The production threshold is 67,108,864 bytes; smaller
thresholds are exercised through the same original method for focused tests.

Workspace uses a 64-byte versioned header, chronological snapshot records, and
then the event queue. Snapshot records store key and value lengths followed by
their bytes; queue records store a key length and key bytes. Header totals,
record boundaries, per-key limits, UTF-8, and queue counts are checked before
mutation. Retired storage is zeroed. Bulk HIA `buffer.copy_range` and
`buffer.move_within` operations preserve byte contents while moving state.

## Resource and execution boundaries

The image-only `history.v1` profile declares 128 MiB input, 128 MiB output, and
256 MiB workspace. It does not change the standard, view, or batch profiles.
Both standalone transport selections are rejected for this wide image profile.
State-capacity preflight occurs before mutation, including the space needed
to append the new event before original threshold eviction. A capacity refusal
is an adapter result and is not treated as an original semantic result.

The original event queue and key set can grow without these fixed limits.
This qualification therefore does not claim unbounded storage or concurrent
`Arc`/`Mutex` ownership. The native poison operation is a controlled observation
of an already-poisoned serial owner, not an implementation of shared mutexes.
The independent Rust oracle actually poisons a `Mutex<HistoryStore>` with a
caught panic, then calls the unchanged original methods under its lock.

The separate static ELF fixture contains two native HIA images. Its root has
only the permission to call the history child; the child has no effect or
outbound-call permission. The fixed syscall adapter provides the transport.

| Image | Input | Output | Workspace | Flags | Call mask |
| --- | ---: | ---: | ---: | ---: | ---: |
| Hex transport | 8 MiB | 8 MiB | 16 MiB | 1 | 2 |
| History owner | 8 MiB | 1,048,608 bytes | 8 MiB | 0 | 0 |

The child image bytes must equal the wide native image bytes. Qualification
checks the complete fixed ELF prefix, table pointers, every descriptor,
source/image digest, padding, compilation receipt, and HIA packing receipt.
The static fixture has its declared smaller domain and does not stand in for
the full 128 MiB tests. It executes with an empty `PATH` and needs no runtime
Python, Rust, libc or dynamic loader.

## Actual qualification

Seven executable native groups retain all 6,198 reference rows: 6,167 original
push/pop operations, 28 lifecycle rows and three poison injections. They include
6,195 actual image invocations (including 31 adapter refusals), 34 static ELF
requests across four real processes, 6,000 deterministic operations across four
private sessions, original examples, stale events, NUL/Unicode/CRLF bytes,
per-file limits, production-byte-cap boundaries, and the full input boundary.
The largest snapshot is 134,217,657 bytes. Sixteen frame refusals, two capacity
refusals and thirteen invalid-state refusals preserve output and state.

The complete original-domain streams are fixed independently of file compression:

| Stream | Complete bytes | SHA256 |
| --- | ---: | --- |
| Requests | 394,117,614 | `5a8d1857c068a4460166a0aada46dc27ae65db3fd7137971c3374fc402f32042` |
| Responses | 321,300,328 | `25bfbb643af8e49ecb060dd2c2b2a5baa33a8be6b98f5f06bb524c47ef49f156` |
| Row ownership | 730,303 | `1f092530dfeff1b76bd8581ac9c25e5f0b1d055b9412ab3e6c61168f64a27a04` |

On the common loader/build source, the complete native suite passed in 19.353
seconds, and four evidence-control groups passed in 10.968 seconds. The latter
refused 16 mutations, including incomplete invocations, consistently rehashed
truncated streams, image and compilation-receipt changes, capacity changes,
rehashed ELF code/table changes, altered static process observations, and source
substitution. Evidence checking adds no native or original semantic executions.
Thirty-six native build artifacts are bound to the capture.

Actual ai395 job `1a1db241f3b-392-18ab` compiled the unchanged original Rust owner
using Rust 1.95.0 and replayed all 6,198 rows. All 321,300,328 output bytes matched.
Compilation and replay took 0.214 and 0.314 seconds respectively on that host.
The result was successful, complete, durable, and source-stable. These separate
host timings are observations, not a comparative performance claim. Source,
binary, invocation and output identities are retained in
`history_original_rust_comparison.json`.

The reproducible qualification performs the native suite and its refusal
controls before compiling and running the original Rust oracle. All native
processes and both Rust steps retain the 180-second limits. The original oracle
source is generated from exact pinned original text and verified before use;
its methods are not translated or replaced with a second expectation model.
The Python collections model used during native execution is an additional
independent check.

The first development capture had six completed native groups and failed its
static fixture invocation because the required CLI arguments were missing.
It is retained as failed. Subsequent complete captures actually reran all
seven groups. The verified bootstrap is reused for component development;
these observations do not claim a new full compiler cold gate or a complete
runtime aggregate pass. Production activation and old-stack removal remain
false until the remaining owners and call sites are implemented and qualified.
