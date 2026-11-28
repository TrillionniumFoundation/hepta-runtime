# Original effect-fence typed JSON projection

`fence_json.hepta` implements the original `OwnerDocument` and `LegacyJobKey`
JSON admission with a native borrowed-buffer entry:

```text
f0(source: readbuf, output: mutbuf, workspace: mutbuf) -> u32
```

This component parses data. The effect-fence controller still owns schema,
owner, phase, state-root, host, job-key and authority checks, descriptor custody,
locks, permits, cache state and error context. No filesystem, process, network or
permission operation is available to this component. It does not replace the
complete effect-fence owner or any public MCP handler.

## Input frame

All integer fields are unsigned 64-bit little-endian values.

| Offset | Field |
| --- | --- |
| 0 | Eight bytes `HFEJSON1` |
| 8 | Kind: `1` for `OwnerDocument`, `2` for `LegacyJobKey` |
| 16 | Exact raw JSON byte length |
| 24 | Raw JSON bytes, with no terminator |

The frame length must be exactly `24 + raw_length`. Owner JSON retains the
original 4,096-byte limit; legacy job JSON retains the original 1,048,576-byte
limit. The limits count raw bytes, including whitespace. Known strings are
decoded to Unicode scalar UTF-8 with no normalization.

The runtime baseline is `a0dcdda1991ec536d5e2d252c006a778993fa566`.
`src/mcp/runtime/effect_owner_fence.rs` has SHA-256
`1e2f2cd32289cd93915076981436b79c04a2756dfc184fa219f043a88f907207`.
The reference oracle copies the two original derive definitions byte-for-byte.
Its dependency versions and registry checksums match the retained runtime lock:
`serde`/`serde_derive` 1.0.229 and `serde_json` 1.0.151 with the original
`float_roundtrip` and `raw_value` features.

## Original typed semantics

Owner maps require `schema: String`, `owner: String`, `epoch: u64`,
`phase: String` and `state_root: String`. `predecessor_state_root` is an optional
string with the original missing-field default. Owner maps reject unknown
fields. Sequence-form Owner JSON accepts exactly five or six elements in that
field order.

Legacy maps require `id: String` and `host: String`. The optional strings
`idempotency_key` and `request_digest` may be omitted or explicitly `null`.
Sequence-form Legacy JSON requires exactly four elements. Both types reject
duplicate known fields, including a repeated optional field whose first value
was `null`; escaped spellings of a known key count as that same key.

Unknown Legacy fields use the original `serde::de::IgnoredAny` behavior. Their
values are skipped by a separate grammar state machine. In this domain the
original parser accepts numeric overflow, lone surrogate escapes and raw
non-UTF-8 bytes inside ignored strings. It also accepts ignored containers
deeper than the generic `Value` recursion limit. Unknown top-level field names
remain strict Unicode strings. Keys inside an entirely ignored object belong to
the ignored-string domain. These distinctions are covered by actual locked-Rust
comparisons; this component does not run a generic `Value` or global UTF-8
precheck before the typed parser.

## Output projection

Success returns the exact output byte length. A 128-byte header is followed by
the decoded strings in the table order. Every unused header byte is zero.

| Offset | Field |
| --- | --- |
| 0 | Eight bytes `HFEJRS01` |
| 8 | Input kind |
| 16 | Optional-string `Some` flags |
| 24 | Owner epoch, or zero for Legacy |
| 32 | First `(absolute_offset, byte_length)` pair |
| 48, 64, 80, 96 | Further pairs as applicable |

For Owner, the string order is `schema`, `owner`, `phase`, `state_root`,
`predecessor_state_root`; flag bit 0 means predecessor is `Some`.
For Legacy, the string order is `id`, `host`, `idempotency_key`,
`request_digest`; flag bits 0 and 1 describe the two optional fields.

`None` has the pair `(0, 0)`. `Some("")` has a nonzero offset and zero length,
and its flag is set. Empty required strings likewise have nonzero offsets.
The parser preserves embedded NUL, newline and other valid scalar content.
Business validation must inspect the decoded bytes rather than treating an
empty string, a NUL or a path-looking value as an authority decision.

## Capacity and refusal

`0xffffffff` rejects a malformed frame or JSON outside the original typed
domain. `0xfffffffe` reports insufficient output or workspace capacity. Both
leave the entire output unchanged. Workspace is private scratch and may change
after admission; no state is carried between requests.

The minimum workspace is 4,096 bytes. An ignored container stack uses two bytes
per active container beginning at byte 4,096; each push checks its full span.
The standard 32 MiB workspace covers the complete one-MiB input domain.
The maximum successful output is bounded by raw JSON bytes plus 128 bytes.
All field parsing, decoded lengths and complete output capacity are checked
before the first output write. Fields and optional flags are reset at every
invocation, including when a previous request failed.

## Evidence and integration

The seven native control groups execute 5,124 direct native calls plus three
actual static ELF runs with an empty `PATH`. They cover field permutations,
required and optional fields, sequence forms, exact length limits, duplicate
keys, all single-byte string/key values, malformed grammar mutations, depth
65,536, output/workspace refusals and reuse after failure. The 5,087 exported
frames were independently replayed through the original derives and locked
Rust crates with zero mismatches. The native request/output hashes are
`d279aad1aace9f809d5b0aa8990de8fc1262036b1eacd40be5e3d770080403b4`
and `d12faf42fa156b19015456e4e7aabe34a046bccda1264d9838929e1ff1ba762c`.

The portable test uses `HIA_FENCE_JSON_MANIFEST` and optionally exports its
actual outcomes to a new `HIA_FENCE_JSON_CORPUS_DIR`. The shared locked-serde
oracle accepts hexadecimal ABI frames on standard input and emits
`status_hex:output_hex` lines. Capacity controls are tested natively; Rust
replay compares the full admitted typed domain rather than an artificial
Rust buffer limit. Compiler bootstrap reuse in development is not a fresh
full cold qualification.
