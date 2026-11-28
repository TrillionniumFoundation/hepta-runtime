# HIA audit typed JSON leaf

This leaf implements the exact six-field `record_schema::Record<S>` and the
four-field Unix `ArchiveAnchor` derives from target
`d3d75c30719db966b004756f610007a7c723729e`.
It has no filesystem, identity authorization, filename, retention, or lifecycle
policy. Those remain the caller's responsibility. In particular these audit
types are distinct from the retained-result store's nine-field record.

The entry point uses the standard HIA `(readbuf, mutbuf, mutbuf) -> u32` ABI.
Buffers are disjoint and valid for their advertised lengths. Workspace is at
least 8192 bytes. Successful return is the number of initialized output bytes.
`0xffffffff` is invalid input; `0xfffffffe` is insufficient capacity. Output is
unchanged on either refusal, and bytes after the successful result are unchanged.
Workspace is scratch after frame admission and need not be preserved.

## Request

All words are little-endian unsigned 64-bit values. The 24-byte frame is
`HAJRQ001`, operation, payload length, followed by exactly that many bytes.

| Operation | Payload | Result |
|---|---|---|
| 1 | At most 2048 JSON bytes | Owned audit record projection |
| 2 | At most 2048 JSON bytes | Archive anchor projection |
| 3 | Canonical audit record projection | Compact original Serde JSON bytes |
| 4 | Canonical archive anchor projection | Compact original Serde JSON bytes |
| 5 | At most 2048 JSON bytes | Borrowed-string audit record projection |

The 2048-byte decode bound is the original audit storage read bound. Encoding
is not limited to 2048 bytes: the storage caller checks its maximum before
opening a destination. The physical request and successful output lengths must
be below `0xfffffffe`, as required by the entry's result representation.

## Canonical projection

The header is 128 bytes, followed by the record's three decoded UTF-8 strings
in declaration order with no gaps. All offsets are relative to this projection,
not the request frame. Empty strings have length zero and still have the
canonical current offset. Anchor projections contain exactly 128 bytes.

| Offset | Audit record | Archive anchor |
|---:|---|---|
| 0 | `HAJPR001` | `HAJPR001` |
| 8 | Kind 1 | Kind 2 |
| 16 | Elapsed present, 0 or 1 | 0 |
| 24 | Accepted milliseconds, low 64 bits | 0 |
| 32 | Accepted milliseconds, high 64 bits | 0 |
| 40 | State: unknown 0, completed 1, failed 2 | 0 |
| 48 | Elapsed milliseconds, 0 if absent | 0 |
| 56 | 0 | 0 |
| 64, 72 | Request ID offset, length | Root device, inode |
| 80, 88 | Owner offset, length | Archive device, inode |
| 96, 104 | Tool name offset, length | 0, 0 |
| 112, 120 | 0, 0 | 0, 0 |

Record decoding preserves the original derived map and sequence forms, required
fields, optional omitted elapsed field, enum string and unit-variant map forms,
duplicate and unknown field refusal, exact integer width, and JSON/UTF-8 rules.
Operation 5 additionally requires the three data strings to be directly
borrowable from the input, as `RecordFields<&str>` does; escaped data strings
therefore fail even when their decoded bytes would otherwise be valid.

Record serialization order is request_id, owner, tool_name, state,
accepted_unix_ms, elapsed_ms. Anchor order is root_device, root_inode,
archive_device, archive_inode. Null elapsed values remain null. Integer
formatting is exact across the full unsigned 128-bit range.

This is a private, typed codec contract. Whole runtime replacement and public
handler qualification require the actual storage and public caller composition.
