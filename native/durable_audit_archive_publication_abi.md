# Audit v12 metadata publication ABI

This private component implements the original `persist_intent(..., initial=true)`, `persist_intent(..., initial=false)`, and `publish_anchor` publication sequences. It does not implement the redb archive, initialize the full layout, or route a public Runtime handler.

## Typed input and ownership

The six-argument HIA entry accepts `HRAAWQ01`, operation (1 initial intent, 2 subsequent intent, 3 anchor), typed-record byte length, and a zero reserved word. The record is the complete `HRAATR01` representation: kind 3 for intent, kind 2 for anchor; format is a u32; device/inode values and shard pairs are u64. Intent may omit the archive identity. The total record length must match its complete shard vector.

There is no new application shard limit. Mechanical capacity must fit the whole immutable request at workspace offset 524288. The qualification allocates max(1 MiB, 524288 + request length); insufficient capacity is refused before effects. The original metadata reader retains its own 256-entry domain, while a valid monotonic update from 256 to 257 entries is still publishable, as in the original writer. Initial publication and anchor serialization do not impose the reader's format or binding checks.

A subsequent intent first invokes the complete actual metadata reader on the same borrowed root descriptor. Known temporary hard-link recovery occurs before monotonic validation. The old record must exist, have format 12, and retain root/legacy identities, any existing archive identity, and the complete shard prefix, with at most one appended shard. The new format is serialized without an additional format-12 restriction.

## Native effects

The HIA actor yields `0xffffffe0`. Its 12-word action at workspace 256 is `HRAAWA01`, sequence, action, slot, span, count, argument, capacity, ACK sequence, result, errno, reserved. The first 64 request bytes are saved independently. The syscall capability checks the full action, complete captured request, capacities, exact owned slots, fixed paths and arguments before an effect or child ACK.

| Action | Meaning |
| --- | --- |
| 1 | Create a private temporary file using exact create-new flags and mode 0600 |
| 7 | Close the owned temporary file |
| 10 | Unlink the exact temporary name |
| 11 | Sync the owned file or borrowed root directory |
| 12 | Obtain the 32-byte random identifier |
| 13 | Write the exact canonical JSON span |
| 14 | Link temporary to the exact final metadata name |
| 15 | Rename temporary onto the exact intent name |
| 100 | Call the actual metadata reader with `HRAAMQ01` operation 1 |

Root slot 0 is borrowed and never closed by this component. Slot 1 is the only owned file descriptor. The five PIC capability entries are create, step, child_ack, take, and destroy. Take always refuses ownership transfer. Entry calls are serialized by one owner. A pending child blocks step and destroy until a single verified ACK; late input, altered child request, repeated ACK, unknown sequence, and mismatched capacity are refused. The context is mmap-owned at workspace capacity plus 8192 bytes and is unmapped using the captured allocation size.

The initial and anchor sequence is create-new temporary, serialize, bounded write-all, file fsync, link final, unlink temporary, directory fsync. A subsequent intent uses rename in place of link/unlink. Serialization occurs after temporary creation and retains the original 65536-byte JSON bound. EINTR and zero-write behavior are explicit. Error cleanup attempts only the current exact temporary name and closes only its owned descriptor; cleanup errors do not overwrite the first publication error. An open failure does not unlink an uncreated name.

## Result

The 128-byte result starts with `HRAAWR01`. Words at offsets 8..88 contain diagnostic, errno, error point, operation, result length, attempted serialized byte count, temporary-created flag, nested reader diagnostic, nested reader point, cleanup-attempt flag, and temporary-name byte count. Remaining words are zero. The serializer records 65537 at the first overflow rather than walking an unbounded oversized vector.

Error points 1..13 respectively identify prior-reader failure, missing old intent, monotonic binding, entropy, temporary open, serialized size, write, zero write, file fsync, link, temporary unlink, rename, and directory fsync. The original first error and effect order remain observable.

## Construction and qualification boundary

The source-bound HIA packer consumes `HRAWPQ01`, version 1, and a zero word. It emits `HRAWPK01`, total length, flat length, and five offsets in create/step/child_ack/take/destroy order, followed by the fixed PIC bytes. GNU as/ld output is an independent byte oracle; actual descriptor tests execute the HIA-emitted, sealed RX image.

Qualification uses the unchanged full original Cargo dependency graph and exact original metadata writer oracle, with filesystem results compared separately from HIA protocol fault-injection controls. This ABI does not grant public routing, cross-thread outer-API ownership, unknown-child replay, or redb qualification.
