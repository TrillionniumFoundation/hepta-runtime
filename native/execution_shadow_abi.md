# Native shadow execution owners

Three HIA sources implement the original shadow execution types, validation,
canonical serialization and digest, plus ordered installed-host composition.
They do not reserve execution, grant final use, spawn processes, contact hosts,
or write a ledger. Accepted results retain `executable: false` and
`status: "shadow_only"` exactly as the original owner does.

This component does not replace the complete runtime. Installed configuration
and public MCP transport have separate identities and qualification. All 125
production handler states and the replacement, activation and removal flags
remain unchanged. The existing stack remains necessary.

## Observed source identities

| Owner | HIA source SHA-256 | Native image SHA-256 |
| --- | --- | --- |
| `execution_shadow.hepta` | `65aa4097e00ed497ab38efe4ddf515de99eaf45abeb7ad2829af4381e7704713` | `3bbc3adac5227351c0baedbf64eeadbf8c64671341bb36f12674ef90ccaf2f08` |
| `execution_json.hepta` | `d1e1610120fcadd72960f04b742ad6bfcfc3bc430a2b828463f3ab2af1268f14` | `d6fd8b1bd60eec2951bd9825edb22b0a5832da2cd99da5117c3169c3c60c0e9a` |
| `execution_controller.hepta` | `5ab993340f2f9bf8b1f6f295098570291307d5bd564332174c2d136454167a10` | `1713343da50f0651d05fa561fd958d3ac14a5cecaa5f97bec13a7f517707419a` |

Compiler: Hepta `d3e2c90173cf733e42b299d0c4274df4b593a12f`, B3 SHA-256
`bfd603dd2b40974d2083b567b4295fb3975938da8435dd636514fc197c485de0`.
These observations are scoped component evidence, not a fresh complete runtime
cold gate. All integers below are unsigned little-endian. Internal frames are
not public MCP parameters.

## Typed record core

`execution_shadow.hepta` accepts a 64-byte header:

| Offset | Value |
| ---: | --- |
| 0 | Eight ASCII bytes `HXSREC01` |
| 8 | Operation 1 |
| 16 | Schema version, representable as `u32` |
| 24 | Generation, `u64` |
| 32 | Class 0–6 in original declaration order |
| 40 | Currentness: current 0, stale 1, unknown 2 |
| 48 | Option bits: cell 1, organ 2, predecessor 4, rollback 8 |
| 56 | Zero |

Fourteen strings follow, each an eight-byte byte length and that many UTF-8
bytes: run, turn, cell, organ, operation, principal, objective digest, policy
digest, candidate digest, host, idempotency key, predecessor, rollback reference,
payload digest. A missing optional string has a clear bit and zero bytes; a
present empty string has a set bit. The frame ends exactly after these fields.

First-error ordering matches the original: schema/generation, first-current
intent, ordinary identities, exactly one cell or organ, digests, rollback
identity, and rollback required for effectful classes. Identities have 1–256
ASCII graphic bytes. Digests have 64 lowercase hexadecimal characters and are
not all zero. This core does not perform host lookup.

Canonical bytes use original struct field order and option serialization. The
digest is SHA-256 of `codex.execution-record.v1`, one zero byte, and canonical
JSON. The 32 KiB canonical budget is retained. The ordinary frozen vector gives
`9ef6afcc1658e9d022a321e0d2decaac71445433c96591a7c1c9afbc5b07f9a9`.

The response is `HXSRSL01` followed by seven `u64` words: tag, canonical length,
digest length, result length, error length, zero, zero. Tag 0 carries canonical
JSON, 64 ASCII digest bytes and original compact result JSON. Tag 1 carries only
the original error text after the header; all success lengths are zero.

Malformed frames return `0xffffffff`; insufficient output/workspace returns
`0xfffffffe`. Neither publishes output. The core needs 64 KiB workspace. The
standalone standard profile admits 8 MiB input; composition uses the existing
`history.v1` capacity declaration with identical native image bytes.

## Typed JSON and original errors

The 32-byte JSON header is `HXSJSN01`, operation, input kind, byte length,
followed by exactly that many JSON bytes.

| Kind | Original type | Successful result |
| ---: | --- | --- |
| 1 | `ShadowExecutionIntentParams` | Typed `HXSREC01` frame |
| 2 | `CanonicalExecutionRecordV1` | Typed `HXSREC01` frame |
| 3 | `CanonicalExecutionBindingV1` | Canonical struct JSON |
| 4 | `CanonicalExecutionClassV1` | Canonical enum JSON |
| 5 | `CanonicalCurrentnessV1` | Canonical enum JSON |
| 6 | Strict `ShadowFinalUseV1` envelope | Canonical envelope JSON |

Operation 1 preserves direct serde acceptance, unknown/duplicate-field
rejection, original struct sequences, optional map fields and unsigned integer
domains. Optional map fields do not permit missing sequence elements. The
adjacent enum accepts its original string-or-map tag in a map; its sequence tag
must be a string identifier.

Operation 2 requires the exact canonical serialization from the separately
qualified generic Value owner. Object keys are sorted, duplicate keys have
their original last-value result, and numbers use original Value formatting.
This operation is not an arbitrary raw JSON deserializer. Success bytes match
operation 1. A typed error is `HXSERR01`, an eight-byte message length and exact
raw serde error text. Earlier syntax/end-of-input errors belong to the Value
owner. The parameter error prefix belongs to the controller.

Diagnostics preserve original missing/unknown fields, variants, types/values,
sequence lengths and enum-map errors, including Rust Debug escaping. Unicode
classification uses the existing independently qualified complete scalar table.
Canonical mode retains the original missing-tag priority when sorted content
appears before a missing adjacent-enum tag.

The parser has explicit workspace accounting and no source-level 8 MiB input
limit. Standalone tests use the standard profile; composed operation uses
`history.v1` so Value numeric expansion can exceed standard input capacity.
These finite profiles do not claim unbounded production input.

## Installed-host controller

Input is `HXSREQ01`, operation 1, canonical argument JSON byte length and bytes.
Output uses the installed configuration owner's `HRCFGM01` shape: status,
diagnostic, payload length, payload. Status 0 carries the shadow result; status
1 carries an original error. Configuration status 2 or 3 remains an explicit
unresolved dependency or capacity outcome.

The fixed native call order is:

1. Image 7 performs canonical typed parameter admission: operation 2, kind 1.
2. Image 0 resolves the exact typed host through installed query operation 4.
3. Image 8 validates and hashes the preserved typed record.

Unknown hosts and unavailable configuration therefore precede schema,
generation, identity and digest errors. Invalid typed parameters never reach
configuration. A successful lookup requires the installed generation, exact
name and internal record shape; its opaque node identity is then discarded.
The controller cannot install configuration or accept caller-supplied host
records.

Typed errors gain exactly `failed to deserialize parameters: `. The actual
rmcp 3.4.1 router converts such parameter diagnostics into a
`CallToolResult::error`. Public transport must retain that result behavior.

Private workspace is 256 MiB, with three disjoint 64 MiB regions at 4,096,
67,117,056 and 134,234,112. Host input reuses the first region after parsing;
the typed record remains intact in the second. The last 256 bytes contain the
`HIACAL01` continuation. Target, region kind, offset, length, capacity, sequence,
completion and error fields are checked before consuming a child response.
Only targets 7, 0 and 8 are emitted. The fixed adapter owns mapping, private
memory and installed configuration lifetime; no syscall authority is granted
by this controller.

## Retained observations and limits

The original core and five original tests were actually compiled remotely with
Rust 1.95 and the feature-resolved 28-package lock. Every dependency identity
was checked against production Cargo.lock. The original matched 73,349 native
cases and 39,009,956 complete output bytes, SHA-256
`361e01960d6ab6b331a6aa9d3bc8c8270a4857a9448187e0825bd20af7e423f6`.
This original recipe includes exact core/tests/result projection; installed
host lookup is qualified separately.

Actual original JSON types matched all 14,960 direct/Value cases and
41,226,842 normalized output bytes, SHA-256
`54ff08730bdb5b472c9d527e0e83b5d560f326ae033af7528dd173b4282f3bdd`.
The diagnostic-enabled source retains the same full stream. Its 7,480 Value
cases additionally match every original result/error: 3,664 typed successes,
1,707 typed errors covering 299 messages and 2,109 earlier syntax rejections.

Controller qualification executes 963 calls with actual typed/core images and
explicit host dependency fixtures. It rejects 28 altered receipts, 15 altered
child envelopes, 27 malformed frames and four insufficient capacities, and
accepts exact output capacity. Persistent sequences remain 3, 6 and 9. These
fixtures do not claim actual installed-host or complete MCP equivalence.
The first observer was killed with exit 137 while both 256 MiB arenas were live.
The unchanged full domain passed when independent Value preparation released
its arena before controller execution.

Original binaries, full compressed output, source recipes, stdout/stderr and
comparison receipts are retained. Failed attempts remain failures. Historical
observations cannot replace fresh mandatory aggregate gates.
