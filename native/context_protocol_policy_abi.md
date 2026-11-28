# Resolved protocol feature policy

This private HIA component implements the two current server decisions after a
trusted native RequestContext owner has resolved its optional ProtocolVersion:
`supports_cache_hints` and `allows_unsolicited_notifications` at target
`d3d75c30719db966b004756f610007a7c723729e`.

## Borrowed-byte ABI

The entry receives `(readbuf input, mutbuf output, mutbuf workspace) -> u32`.
All words are little-endian u64. Input has exactly 32 header bytes followed by
the complete UTF-8 bytes of the already decoded optional version string.

| Offset | Request field |
| --- | --- |
| 0 | Eight-byte magic `HCPOLQ01` |
| 8 | Operation, exactly 1 |
| 16 | Version present, exactly 0 or 1 |
| 24 | Version byte length, exactly input length minus 32 |
| 32 | Complete version bytes |

Absent versions require a zero length. Present empty strings are distinct from
absence. The UTF-8 validity of a present string belongs to the upstream typed
ProtocolVersion decoder. This owner does not accept raw JSON, resolve metadata
or peer precedence, authenticate a caller, or select a connection mode.

The output capacity must be at least 32 bytes. Success returns 32 and writes:

| Offset | Response field |
| --- | --- |
| 0 | Eight-byte magic `HCPOLS01` |
| 8 | Version present, unchanged |
| 16 | Cache hints allowed, 0 or 1 |
| 24 | Unsolicited notifications allowed, 0 or 1 |

The SDK's ProtocolVersion uses string ordering. A present version at least
`2026-07-28` permits cache hints and forbids unsolicited notifications. Every
other resolved value, including absence, has the opposite pair. The component
compares at most the first ten bytes, including exact-prefix and short-prefix
cases; it does not interpret the string as a calendar date.

Malformed descriptors and output capacities below 32 return `0xffffffff`
without changing output or workspace. Success changes only the first 32 output
bytes. The input and complete workspace remain unchanged on every path.

## Qualification state

This source was authored while the local execution environment was unavailable.
It is not yet compiled or qualified. The independent recipe must compile it
with pinned Hepta `d3e2c90173cf733e42b299d0c4274df4b593a12f`, call the two unchanged
original Rust helpers under RMCP 3.9.0 / Rust 1.95.0 in CI, retain complete raw
calls and source identities, and independently reread that capture.

All production, complete RequestContext resolution, complete SDK, complete tool
routing, whole-runtime replacement and old-stack removal claims remain false.
