# Retained-storage typed JSON

`request_storage_json.hepta` implements the original serde derives for retained
result `Record`, `ResultState`, `ArchiveAnchor`, `DirectoryIdentity` and
`ArchiveMarker`. Its source SHA256 is
`3dca192460879ca124649f17bfa753f8aabf76a734b0560e9096f1c723007128`.
The module has 32 functions, including ten exact relocated helpers from the
qualified `fence_json.hepta` Unicode and JSON grammar owner.

This component preserves typed values. File ownership, permissions, link count,
directory identity bindings, schema value 2, exactly 256 shards, valid request
identities, payload integrity and publication belong to the storage owner.
Successful parsing alone does not perform or qualify those checks.

## Frame and limits

The common borrowed-byte entry is `(readbuf, mutbuf, mutbuf) -> u32`. The request
has ASCII `HRSTQ001`, a little-endian u64 kind at offset 8, an exact u64 raw JSON
length at offset 16, and the JSON bytes at offset 24. Kinds are 1 for Record,
2 for ArchiveAnchor and 3 for ArchiveMarker. Record and anchor raw bytes are
limited to 98,304; marker raw bytes are limited to 1,024. Whitespace counts toward
these limits. The workspace is at least 1 MiB.

All maps reject unknown or duplicate fields, including equivalent escaped keys.
Record maps require the first six fields, while the three optional payload
fields may be absent or null. Record sequences require all nine elements in
original field order. Anchor sequences require six elements, marker sequences
two and DirectoryIdentity sequences two. Required strings use strict Unicode
scalar decoding, preserve embedded NUL and distinguish an empty string from an
absent optional string.

The acceptance timestamp is an exact u128. Four u32 limbs implement checked
decimal accumulation without conversion through floating point. Directory
identities and optional payload length use u64, and schema uses u8. Floating
point syntax, overflow, negative values and invalid JSON number grammar are
rejected in those unsigned fields. ResultState admits its original string form
and externally tagged unit form, such as `{"stored":null}`.

The projection retains every typed shard entry admitted by the raw byte bound;
it does not turn the later 256-shard business rule into a parsing quota. Actual
qualification includes a 16,000-entry anchor sequence.

## Projection

Success produces a zero-initialized 256-byte header followed by strings or
directory pairs. All integers are little-endian u64.

| Offset | Field |
|---|---|
| 0 | ASCII `HRSTJ001` |
| 8 | Kind |
| 16 | Record optional presence bits: Base64 1, payload length 2, SHA256 4 |
| 24 | Record timestamp low word, or anchor/marker schema |
| 32 | Record timestamp high word |
| 40 | Record state: unknown 0, stored 1, overflow 2, refused_dto 3, not_completed 4 |
| 48 | Optional Record payload length; zero when absent |
| 56 | Anchor shard count |
| 64 onward | String offset/length pairs or fixed directory identities |

Record string pairs are request ID, owner, tool name, policy binding, payload
Base64 and payload SHA256, at offsets 64, 80, 96, 112, 128 and 144. Marker has
one string pair at 64. Each pair uses an absolute offset into the output and
a decoded UTF-8 byte length. None is `(0,0)`; Some of an empty string has a
nonzero offset and zero length. Present string bytes begin at offset 256.

Anchor header offsets 64, 80, 96 and 112 contain `(device,inode)` for root,
legacy, store and archive. Its shard `(device,inode)` pairs begin at offset 256.

Malformed frames or JSON outside the original typed domain return `0xffffffff`.
Insufficient output or workspace returns `0xfffffffe`. Both leave the entire
output unchanged. Parsing may change private workspace, which is reset for
each invocation. Input bytes are never changed. This typed ABI does not reproduce
the original serde error string and location; its later caller must retain its
own original error exposure contract before public activation.

## Actual evidence

The fresh compiler is fixed to Hepta
`d3e2c90173cf733e42b299d0c4274df4b593a12f`, B3 SHA256
`bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0`.
Both the parser and standalone filter packer are freshly compiled from HIA.
The native ELF runs with an empty PATH and requires no Python, Rust or libc.

The unchanged five original derive blocks are copied from runtime
`request_results.rs` SHA256
`f1003ad4de7448d601d0536d3a7c4f0d72790e732e8301d6c36349035ca3c439`.
Rust 1.95.0 builds the actual reference using eleven original locked registry
packages. Each cached crate archive is verified against its original Cargo.lock
checksum, and every archive member is compared to the source used for compilation.
The sources are checked again after execution.

Actual job `1a1de6f41ac-392-23de` succeeded with complete durable logs. Its 4,221
native/original comparisons match exactly: 3,352 admitted projections and 869
refusals. The 21 separate capacity/output-preservation controls yield 4,242
borrowed native entries; three additional actual native ELF processes reproduce
the corresponding original projections. The full fresh qualification took
5.97 seconds. Coverage includes integer boundaries, 512 random u128 values in
both map and sequence form, optional presence, all enum forms, field permutations,
escaped duplicates, raw byte/Unicode mutations, exact input limits and large
shard vectors. The v1 missing-checksum-metadata harness failure is preserved;
the v2 runner verifies actual crate archives and member bytes instead.

Result storage, audit storage, public dispatch and whole-runtime replacement
remain unqualified by this parsing component.
