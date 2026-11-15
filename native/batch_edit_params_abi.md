# HIA `BatchEditParams` projection

This owner implements the original `BatchEditParams` custom deserializer,
`BatchEditOperation` derive and `string_or_lines` conversion in
`src/mcp/server.rs`. It accepts the canonical JSON object delivered by the
existing native JSON Value owner. Raw JSON parsing, SDK capability validation,
request dispatch and all filesystem effects are separate owners. The private
frame is not an authentication or session capability.

The exact original Rust source is retained and checked by the independent
`batch_edit_params_oracle`. Successful projection is not a completed batch edit.
This component does not replace the public route or qualify whole-runtime
removal.

## Input and output

All words are little-endian u64. Entry `f0(readbuf, mutbuf, mutbuf) -> u32` uses
disjoint borrowed input, output and private scratch buffers.

Input is `HBPRQ002`, the canonical JSON byte length, a zero word, and exactly
that many bytes. The admitted semantic domain is a canonical JSON object from
the native Value owner: sorted unique keys, canonical numbers and strings. The
projection validates the complete JSON grammar before inspecting fields. This
is a private typed handoff, not a second public raw JSON decoder.

The native success return is always 64. The fixed response is:

| Offset | Meaning |
|---|---|
| 0 | `HBPRR002` |
| 8 | Status: 0 typed result, 1 original typed diagnostic, 2 grow scratch, 3 grow output, 4 unrepresentable extent |
| 16 | Decoded path byte length, only for status 0 |
| 24 | Canonical normalized parameter byte length, only for status 0 |
| 32 | Typed operation count, only for status 0 |
| 40 | Diagnostic byte length, only for status 1 |
| 48 | Required complete capacity for status 2/3; u64 maximum for status 4 |
| 56 | Zero |

Status 0 carries decoded path UTF-8 followed by the complete canonical JSON
serialization of the typed params. Status 1 carries the exact original serde
diagnostic, without the SDK's surrounding `failed to deserialize parameters:`
text. Status 2/3/4 carries no body. A growth response changes only the fixed
header, never a partial body. Unused output tail remains unchanged.

Malformed private framing/grammar returns `0xffffffff`; fewer than 64 output
bytes returns `0xfffffffe`, with output unchanged. Scratch is disposable private
state. It contains offsets and traversal state, not persistent request identity.
An input or output mapping must not be moved while borrowed by an invocation.

All extent accounting is u64 with explicit overflow handling. The two-pass
serializer preflights complete output capacity before copying the result.
Traversal scratch grows with actual nesting; there is no independent operation
count, string length or cumulative result quota. Build profiles still declare
their actual buffer capacities. A later dynamic adapter must fulfill growth or
report its actual resource failure without inventing a tool-domain error.

## Preserved parameter behavior

The raw struct validates `operations` as an array and optional `path` as a
string/null before path hoisting. It scans all operation objects and removes
their `path` keys before any operation is decoded. An explicit top-level string
path wins, including an empty string. Otherwise exactly one distinct per-op
string path is required; non-string per-op paths are ignored after removal.
Missing/conflicting path errors precede operation type errors.

Operation objects and four-element sequences use the original serde behavior.
The operation enum accepts its lowercase string and single-key unit-map forms.
`start` is an arbitrary required Value, including null. `end` defaults to null.
Content accepts a string or an array of strings joined by LF. Wrong content
values use the original compact Value display; unknown enum names retain the
original decoded string in backticks. Other type errors preserve Rust Debug
string formatting through the already qualified Unicode table.

Empty operation arrays and arrays longer than 50 are valid typed values. The
original body rejects them later, after SDK extraction and the method's effect,
session and policy ordering. This owner does not impose the View result gate;
the original batch-edit body has no such 8 MiB output restriction.
