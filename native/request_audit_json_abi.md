# Native audit metadata typed JSON

`request_audit_json.hepta` decodes the original owned `Record<String>`,
`DurableState`, legacy `ArchiveAnchor`, `ShardAnchor` and `InitIntent` derives.
Its source SHA256 is
`f74fdc64d731878e1f943b6dfed84c5cae034eceb6b8b2336ae9f3ebc8b1e0f8`.
The module has 32 functions, including ten exactly relocated functions from
the existing `fence_json.hepta` Unicode and JSON grammar owner.

This owner produces typed values for later storage operations. It does not
validate filesystem permissions or identity bindings, acquire locks, check
the active-request registry, publish records, create a durable admission, or
dispatch a production tool. The typed format value and shard count remain
distinct from the archive owner's business rules.

## Input

The entry is `(readbuf input, mutbuf output, mutbuf private) -> u32`.
Integers in this private ABI are little endian. The workspace is at least
1,048,576 bytes. Input is immutable and there are no continuations.

| Offset | Meaning |
|---|---|
| 0 | Eight ASCII bytes `HRAJQ001` |
| 8 | Kind: 1 Record, 2 legacy anchor, 3 shard anchor, 4 initialization intent |
| 16 | Exact raw JSON byte length |
| 24 onward | Raw JSON bytes |

Kinds 1 and 2 admit at most 2,048 raw bytes. Kinds 3 and 4 admit at most
65,536 raw bytes. Whitespace counts toward the bound. The adapter applies
these existing storage bounds before typed parsing; it does not claim that
serde's standalone parser itself imposes those limits.

Maps reject unknown and duplicate fields, including equivalent escaped keys.
Struct sequences use original field order and exact element count. Missing
map `elapsed_ms` and initialization `archive` become `None`; present `null`
has the same optional value. Each fixed identity is an exact two-element
`[u64; 2]` sequence, so a device/inode object is rejected. Shard vector length
is not silently restricted to 256 at this typed layer.

Record fields are `request_id`, `owner`, `tool_name`, `state`,
`accepted_unix_ms` and `elapsed_ms`. Strings preserve Unicode scalar values,
escapes, empty strings and embedded NUL. Acceptance timestamps preserve the
complete u128; elapsed milliseconds and identity words preserve u64. Archive
format preserves u32. Numeric overflow, floating syntax and negative syntax
are refused in those unsigned fields.

Durable state accepts the original string form and externally tagged unit
form, including `{"unknown":null}`, `{"completed":null}` and
`{"failed":null}`. Other enum variants are refused.

## Successful projection

Every result starts with a zero-initialized 256-byte header. The first eight
bytes are `HRAJJ001`; offset 8 repeats the kind. Unless described below,
header words remain zero.

| Offset | Record | Shard anchor or initialization intent |
|---|---|---|
| 16 | Elapsed presence, 0 or 1 | Intent archive presence, 0 or 1; zero for shard anchor |
| 24 | Timestamp low 64 bits | Format as u64 |
| 32 | Timestamp high 64 bits | Zero |
| 40 | Unknown 0, completed 1, failed 2 | Zero |
| 48 | Elapsed milliseconds; zero when absent | Zero |
| 56 | Zero | Shard count |
| 64 onward | Three absolute offset/length pairs | Root, legacy and archive identity pairs |

Record strings are request ID, owner and tool name, concatenated from offset
256. Each offset/length pair begins at 64, 80 or 96. A present empty string
retains its nonzero absolute offset.

The legacy anchor has four u64 words at 64, 72, 80 and 88: root device, root
inode, archive device and archive inode. Its projection is exactly 256 bytes.
Shard and intent identity pairs occupy offsets 64, 80 and 96; absent intent
archive yields a zero pair and presence zero. Shard pairs follow from 256.
The presence bit distinguishes `None` from a present `[0,0]`.

Malformed frames or rejected typed JSON return `0xffffffff`. Insufficient
output or private capacity returns `0xfffffffe`. Both leave all output bytes
unchanged. A private capacity refusal also leaves the workspace unchanged.
Parsing may change private workspace; it is reset on the next admitted call.
This ABI does not expose serde's diagnostic string or line/column location.

## Actual original comparison

The reference includes eight unchanged original source blocks from
`request_audit.rs` and `request_archive_store.rs`, including the original
generic Record declaration and both type aliases. Rust 1.95.0 freshly builds
the reference from eleven original locked packages. Every crate archive and
source member is checked, as are original blocks, helpers and inputs before
and after execution. The native build uses the pinned Hepta compiler and
freshly compiles both the HIA module and the standalone filter packer.

Actual remote job `1a1df4a2a68-392-26d1` completed successfully in 6.10 seconds.
Its 3,390 original/native comparisons match every projection byte: 2,538
accepted inputs and 852 refusals. It also passed 28 separate output-capacity,
workspace-capacity and output-preservation controls, for 3,418 borrowed native
calls. Four actual native ELF executions with an empty PATH reproduce the
four original projections. The ELF has no Python, Rust or libc semantic
dispatcher.

Coverage includes all field permutations for these structs, escaped duplicate
keys, missing optional fields, map and sequence forms, enum representations,
u32/u64/u128 boundaries, 512 random full-width timestamps in both Record
forms, every single raw byte in a JSON string, Unicode escapes, tuple shape
refusals, complete raw-size boundaries and vectors including 10,000 admitted
identities. A vector whose encoded input exceeds its byte bound is recorded
as an adapter refusal, not as a serde limitation.

Full result storage, audit storage, concurrent locking, production activation,
public request dispatch and old-stack removal remain unqualified.
