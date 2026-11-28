# Native audit retention policy

This private three-buffer HIA entry implements the unchanged target
`archived_copy_matches`, `retain_before_begin`, and `retain_for_batch` policy.
It does not perform file I/O, substitute an activity registry, sort records, or
construct public error messages. The caller holds the existing store lock and
executes each requested effect before resuming this actor.

`f0(readbuf request, mutbuf response, mutbuf workspace) -> u32` requires disjoint
buffers. The source is immutable for one invocation. An accepted initialization
copies the full typed input into the exclusive workspace; the caller can release
that source immediately. The workspace is opaque and must remain unchanged by
the caller between invocations. Separate invocations own separate workspaces.

All words are little-endian u64. A valid invocation writes exactly 128 response
bytes and returns 128. `INVALID = 0xffffffff` and `CAPACITY = 0xfffffffe` leave
both mutable buffers unchanged. Bytes beyond the output prefix and the initial
workspace extent remain unchanged. Frame lengths must be less than CAPACITY.

## Initialization

The header has 128 bytes and magic `HATRQ001`. Word offsets are:

| Offset | Meaning |
| --- | --- |
| 8 | Operation 1: retain_before_begin; 2: retain_for_batch |
| 16 | Original record count N |
| 24 | Pending string count P |
| 32 | Sync directory flag, 0 or 1 |
| 40, 48 | Requested owner offset and byte count |
| 56 | Record descriptor offset, exactly 128 |
| 64 | Pending descriptor offset, exactly 128 + 16N |
| 72 | First record payload offset |
| 80 | Complete frame byte count |
| 88..127 | Zero |

Each descriptor is `(offset, length)`. Layout is the header, N record
descriptors, P pending string descriptors, the owner UTF-8 bytes, N canonical
record projections in their original order, then P UTF-8 strings. All regions
are contiguous, with no extra bytes or noncanonical offsets. Duplicate pending
strings have ordinary HashSet membership semantics. Operation 1 requires P=0
and sync=1; operation 2 permits either sync flag.

Records use the closed audit JSON leaf's `HAJPR001` projection: 128-byte header,
kind 1 at offset 8, elapsed presence at 16, u128 accepted time split at 24/32,
state unknown/completed/failed as 0/1/2 at 40, elapsed at 48 (zero when absent),
and request_id/owner/tool_name offset/length pairs at 64/72, 80/88, 96/104.
Offsets 56, 112 and 120 are zero. UTF-8 string bytes are contiguous from 128.

The response needs at least 128 bytes. Workspace needs `128 + 8N + frame.len`
bytes. There is no native 128/512 allocation limit: these values are the
original retention thresholds, not buffer capacities.

## Effect response

Resume requests have a 64-byte header, the same magic, and operation 3:

| Offset | Meaning |
| --- | --- |
| 16 | Exact sequence from the outstanding response |
| 24 | Outstanding effect kind: 1 active, 2 archive read, 3 remove |
| 32 | Effect status, defined below |
| 40 | Opaque nonzero error token on an error; zero otherwise |
| 48 | Payload bytes after the header |
| 56 | Zero |

Active status 0 means inactive, 1 means active, and 2 means error. Archive
status 0 carries one canonical Record projection, while 1 means read error
and has no payload. Remove status 0 means success and 1 means error; neither
has a payload. Other combinations, wrong effect types, stale sequence values,
and resumes after completion are refused before changing the actor.

The caller retains the actual error behind each nonzero token. Active and
remove errors propagate the same token. Archive read errors make that candidate
ineligible. The HIA policy compares the returned archived owner, tool, full
u128 time, state and elapsed value itself. As in the target function, it does
not additionally compare the archived request_id; the archive reader owns its
filename binding.

## Responses and remaining records

The response magic is `HATRS001`:

| Offset | Meaning |
| --- | --- |
| 8 | Kind 1 active, 2 archive read, 3 remove, or 4 complete |
| 16 | Effect sequence (last sequence at completion) |
| 24 | Original record index; u64::MAX at completion |
| 32 | Sync flag only for remove, otherwise zero |
| 40 | Completion result: 1 true, 2 false, 3 error; zero while waiting |
| 48 | Error token only for error completion |
| 56 | Remaining live record count |
| 64 | Number of successful removals |
| 72 | Remaining requested-owner count |
| 80 | Workspace base of the copied initialization frame |
| 88 | Original record count |
| 96 | Complete used workspace extent |
| 104..127 | Zero |

For active, pass the selected record's request_id to the actual activity
registry. For archive, read `request_id + ".json"`. For remove, pass the whole
selected Record and the emitted sync flag to the existing guarded remove
operation. Consume each effect exactly once, then resume.

Workspace starts with `HATRW001`; the live original-index vector begins at 128.
Its length is the response's live count. The copied input begins at
`128 + 8N`. The first live-count indexes identify the final or partial vector
in its original order. The unused index suffix is not an additional record.
Successful removals persist in this vector on later false/error completion.
A remove error leaves its selected record in the vector, even if the underlying
remove operation had already unlinked a file before a directory-sync error.

The owner quota is processed first while count >=128. Only after it succeeds
does the global phase process length >=512. Each scan restarts at zero after a
successful removal. Foreign owners in the owner phase and pending request IDs
skip all downstream effects. Active queries and archive reads are repeated on
later scans; eligibility is never cached.

## Qualification boundary

The reference uses the three unchanged original Rust function bodies and exact
Record type, with mechanical effect fixtures replacing only their external
activity/archive/remove boundaries. It compares each ordered effect argument,
effect result, final return value, and complete ordered remaining Record vector.
The HIA runner records complete before/after source, output, workspace, guards,
and native return for every invocation. Actual persistence, store-lock
composition and public request callers require their own integration proof.
