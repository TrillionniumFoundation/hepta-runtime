# Current target catalog policy: private three-buffer leaf

This component implements current Tool visibility and schema policy, bound to
target `d3d75c30719db966b004756f610007a7c723729e`. It does not execute the 136
tool bodies or qualify public routing, worker readiness, asynchronous scheduling,
production activation or old-stack removal.

## Inputs and authority

The author reads only `catalog_policy.pseudo` and `declarations.json`. The latter
contains the actual 136 raw Tool declarations and original runtime, HIA and weight
name lists. It contains no list-case, expected-result or server-info wire.
`catalog-input.json` is the exact raw declaration array. Expected handler wires
belong exclusively to the independent reference and comparator.

All words are unsigned little-endian u64. The HIA entry takes separate read-only
source, mutable output and mutable workspace buffers and returns u32.

| Request offset | Meaning |
| --- | --- |
| 0 | `HCATCQ01` |
| 8 | Operation 1 catalog, 2 ordinary schema qualification, 3 frozen schema qualification |
| 16 | Trusted configuration: runtime bit 0, HIA bit 1, REA profiles bit 2, weight workers bit 3 |
| 24 | Modern typed-result policy, 0 or 1 |
| 32 | Exact payload byte length |
| 40, 48, 56 | Zero |
| 64 | Complete raw Tool array for operation 1; complete schema object for operations 2 and 3 |

Catalog flags are exactly 0 or odd values from 1 through 15. Schema operations
require flags and modern zero. The entire request is at most 8 MiB. Catalog mode
requires all 136 expected Tool names in original sorted order, object-valued
Tools and object-valued `inputSchema`. Configuration selection belongs to the
caller; this leaf grants no authentication or execution authority.

| Reply offset | Meaning |
| --- | --- |
| 0 | `HCATCR01` |
| 8 | Status 0 success, 1 JSON/shape refusal, 2 required workspace, 3 required output |
| 16 | Success payload offset 64, otherwise zero |
| 24 | Success payload length; status 2/3 exact required total capacity; refusal zero |
| 32 | Visible tool count on catalog success, 1 on schema success, otherwise zero |
| 40, 48 | Original flags and modern |
| 56 | Zero |
| 64 | Complete JSON on success only |

The return is the full success extent or 64 for framed refusal/growth. Invalid
frame fields return `0xffffffff` without writing mutable buffers. Output shorter
than 64 returns `0xfffffffe` without writing. Framed errors/growth write only the
64-byte reply. A caller retries exactly the same input after a capacity grant.
Parsing and policy state resets on every invocation; prior workspace is untrusted.

## JSON and policy

The nonrecursive parser validates complete JSON grammar, UTF-8, Unicode escape
pairs and up to 128 container levels. An exact-count pass precedes the linked
96-byte-node AST. Scalars retain input spans. Decoded duplicate object keys use
last value. Number grammar is checked here; the mandatory following serde Value
owner performs finite numeric conversion. The qualified primary input is the
original serde-produced declaration array. This is not a substitute general
RawValue/arbitrary-number deserializer.

The null pass applies bottom-up to every ordinary schema root value, not to the
root itself. It removes null type variants, collapses the permitted singletons,
and merges anyOf then oneOf only into absent parent keys. The noise pass removes
`$schema`, `format` and null `default` in schema contexts. `properties`/`$defs`
are named maps; only direct object values receive schema treatment. Arrays
receive noise treatment only on direct object entries. All 11 HIA and 6 specified
REA schemas remain unchanged.

Visibility order is HIA config, REA static profiles, weight workers, then
runtime/shell selection, retaining router order. Typed list construction always
contains `resultType: complete`; modern adds `ttlMs: 0` and `cacheScope: public`.

The complete wire-equivalence pipeline is:

1. Policy success payload.
2. Native serde `HSJVAL01`, operation 1, payload length and payload. Its full
   return is canonical JSON Value.
3. Target SDK 3.9 native catalog `HRRSP001`, operation 4/policy 0, canonical
   length and body. Its `HRRPO001` response has kind 4, flags 0, offset 64, full
   wire length, and zero policy/reserved words.

All 216 original handler observations map to 18 distinct complete ABI request
strings (9 configurations times 2 modern classes). The comparator establishes
each class by byte equality and retains every original protocol, cursor and
expected wire. Actual native calls are counted independently of comparisons.

## Workspace and implementation evidence

Header/temporaries occupy 0..1023. The parser stack occupies 1024..6143; field
table 6400..6559; literal data starts at 7168; packed names start at 8192 and end
before 16384. Nodes begin at 16384 with stride 96. Required workspace is exactly
16384 + 96 times counted nodes. Serialization reuses the retired parser stack
and measures the entire result before publishing any JSON.

The v2 ASCII path changes only `string_end`: ordinary printable ASCII advances
directly; quotes terminate; controls, escapes and high-bit bytes use the unchanged
decoder. All other 41 function bodies match v1 byte-for-byte. The retained v1
partial development run is interrupted and has no completed qualification claim.
