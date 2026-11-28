# Durable audit legacy anchor

This component implements the original retained legacy-anchor contract from
`src/mcp/runtime/request_archive_store.rs`. It is a private archive component.
It does not implement the public archive query, v12 shard recovery, or the redb
index. The source relation retains the original Rust functions and tests as an
independent qualification oracle.

## Ownership

A caller supplies one already admitted and retained audit-root descriptor through
a private runtime capability. The root descriptor is borrowed throughout the
component's lifetime. The only descriptor acquired by this component names
`.request-archive-v11-anchor.json` relative to that root. The component retains
that actual descriptor and the full original bytes between operations. A public
request cannot supply a descriptor, filename, syscall number, or child identity.

The HIA actor owns policy, comparisons, action ordering, retry decisions and
error classification. The mechanical engine executes only the closed actions
below. The typed child is the LegacyAnchor operation of
`durable_audit_archive_records.hepta`; its input and output remain private.

The actor uses the ordinary six-argument native HIA ABI. The mechanical engine
uses five separately typed System V entry points; it is not callable through the
public request ABI. Its executable bytes are produced by
`durable_audit_anchor_packer.hepta`. The independently assembled
`durable_audit_anchor_engine.S` is qualification and authoring provenance.

## Public-to-component frame

The request is exactly 32 bytes: `HRAANQ01`, operation, zero, zero, with all
numeric fields little-endian u64.

| Operation | Meaning | Initial state |
| --- | --- | --- |
| 1 | Open and admit the fixed anchor | Entire workspace zero |
| 2 | Fence the retained anchor | Open and previously admitted |
| 3 | Release the owned anchor | Open and previously admitted |

The output capacity is at least 192 bytes and workspace capacity at least 16384
bytes. Both actual capacities are retained on first entry and must match on
every continuation. The complete original request is retained during a yielded
operation. A different operation cannot replace an outstanding request.

Return values are `0xffffffe0` for a private action, `0xffffffff` for invalid
input/state/confirmation, `0xfffffffe` for insufficient capacity, and 192 for
a completed component response. A completed response starts with `HRAANR01`:

| Byte offset | Value |
| --- | --- |
| 8 | Diagnostic: 0 success, 1 admitted operation failed |
| 16 | Original syscall errno, or zero for a policy refusal |
| 24 | Failure point |
| 32 | Request operation |
| 40 | Response length, exactly 192 |
| 48 | Object state: 1 retained, 2 closed |
| 56 | Zero |
| 64..191 | Complete typed LegacyAnchor result on retained success; otherwise zero |

Invalid input is distinct from an admitted operation's refusal. A fence refusal
keeps the original object and descriptor retained until explicit release. An
open refusal closes any descriptor already acquired during that open.

## Closed private actions

At workspace offset 256 the HIA actor writes twelve u64 words:
`HRAANA01`, sequence, kind, slot, span, count, argument, capacity,
acknowledged sequence, result, errno, zero. The first eight words are frozen
before an effect. A confirmation must preserve every frozen word and match the
exact sequence. The actor additionally binds its complete original request.

| Kind | Effect | Fixed argument domain |
| --- | --- | --- |
| 1 | openat | Borrowed root; fixed anchor name; O_RDONLY, O_NONBLOCK, O_NOFOLLOW, O_CLOEXEC |
| 2 | fstat | Owned anchor; eleven metadata words |
| 3 | geteuid | No descriptor or path |
| 4 | fstatat | Borrowed root; same fixed anchor; AT_SYMLINK_NOFOLLOW |
| 5 | read | Owned anchor; the original 2048+1 byte bound |
| 6 | pread | Owned anchor; offset and range within the retained original bytes |
| 7 | close | Owned anchor only; ownership is retired before the syscall |
| 100 | Typed HIA LegacyAnchor child | Fixed typed request and result spans |

The eleven metadata words are device, inode, mode, uid, gid, link count, size,
mtime seconds, mtime nanoseconds, ctime seconds and ctime nanoseconds. This is
the full original AnchorStamp. It must not be substituted with the separate
audit-root metadata format.

The private engine context owns its mmap and anchor descriptor. Its root
descriptor is borrowed. The five entry points are:

- `create(0, workspace, workspace_capacity, root_fd)`
- `step(context)`
- `child_ack(context, result_length, errno)`
- `take(context, slot)`, always refused with EPERM
- `destroy(context)`

A pending typed child prevents both another step and destruction. The caller
must establish that the child has finished or was never dispatched before
confirming cancellation. An unconfirmed child cannot be converted to a
successful cancellation. Duplicate or mismatched confirmations are refused
without repeating the original effect.

## Original order and retained bytes

Open performs the original no-follow open, held metadata/policy check, named
metadata comparison, bounded complete read, repeated held/named comparisons,
then the actual typed HIA parse. The mode is exactly 0600, uid must match the
current effective uid, link count is one, the object is a regular file, and
the retained length cannot exceed the original 2048-byte bound.

A fence first validates the retained policy against the current effective uid,
then compares the complete held and named metadata. Positional reads compare
every retained byte without moving the shared descriptor cursor. Held and named
metadata are read again afterwards. Matching timestamps do not substitute for
the byte comparison. EINTR may resume the same read; close is never replayed.

The component preserves the original policy refusal, binding change, changed
while reading, missing name, byte change, EOF and syscall error domains. The
qualification records raw original errors, HIA failure points and every actual
syscall action, so an error-category summary does not replace the original
evidence.

## Qualification boundary

The fixed original nine pinned-anchor methods run in the original full Cargo
dependency and release profile. Separate paired filesystem cases exercise the
actual HIA actor, actual typed HIA parser and the HIA-emitted mechanical code.
The engine is mapped from sealed bytes and has no Python filesystem callback;
Python creates qualification fixtures and observes actual results.

Typed data qualification, native compilation, filesystem comparison, and the
public durable-request interface are separate results. None of those results
alone qualifies v12 initialization/recovery, redb persistence, global archive
registry lifetime, or the ten public durable-request handlers.
