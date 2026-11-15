# Typed Text Editor parameters

`text_editor_params.hepta` owns the typed projection of the unchanged
`TextEditorCommand` and `TextEditorParams` declarations in target runtime
`737acf6f901e46c57b0b4374e323e0d1132e0d49`. Its reference dependency profile is
serde 1.0.229, serde_json 1.0.151 with `float_roundtrip` and `raw_value`, and
schemars 1.2.2. No filesystem operation, public dispatch, SDK connection,
effect permit, cache publication, or complete runtime replacement is implied.

## Input

The borrowed three-buffer entry takes a 24-byte `HTEPRQ02` header: magic,
little-endian u64 JSON length, reserved zero, followed by exactly that JSON.
The JSON is the canonical map returned by the shared `serde_json_span.hepta`
`HJSMS002` operation 1. The map root preserves ordinary keys while its values
use the shared typed Value/RawValue semantics. The projection itself performs
no additional generic Value re-entry and never delegates decisions to a host
JSON parser.

All six fields are checked in canonical map order. `command` and `path` are
required; missing-field errors are emitted after visiting the map. The optional
string fields `content`, `old_text`, and `new_text` and optional boolean
`replace_all` retain the distinction between absence/null and present empty or
false values. Unknown fields are ignored. The command accepts serde's string
or single-key unit-map representation for `create`, `str_replace`, `delete`,
and `undo_edit`. Unknown variants, map cardinality, non-unit payloads and
unexpected scalar types retain their complete original diagnostic bytes.

Missing `content` is a valid optional typed value. The eventual Create body
must check it at its original point after public admission; this component
does not move a body-level error before the effect fence or session owner.

## Output

The entry returns 128 for a complete fixed `HTEPRR02` header. Payload bytes
follow the header and are included in its lengths, even though the entry's
scalar return remains 128.

| Byte offset | u64 field |
| --- | --- |
| 0 | `HTEPRR02` magic |
| 8 | Status: 0 typed success, 1 typed error, 2 workspace growth, 3 output growth, 4 unrepresentable extent |
| 16 | Command: 1 create, 2 str_replace, 3 delete, 4 undo_edit |
| 24 | Path byte length |
| 32 | Presence bits: content 1, old_text 2, new_text 4, replace_all 8 |
| 40 | Content byte length |
| 48 | Old-text byte length |
| 56 | New-text byte length |
| 64 | Boolean value, zero or one |
| 72 | Diagnostic byte length |
| 80 | Required capacity for growth; u64 maximum for unrepresentable extent |
| 88–127 | Reserved zero |

Success payload order is decoded path, content, old_text, and new_text. Error
payload is the complete UTF-8 serde diagnostic. Fields unrelated to the
selected status are zero. Errors use two passes so an output-growth response
does not publish a partial diagnostic. Bytes after the declared result extent
are preserved.

Malformed private framing returns `0xffffffff`. Output capacity below 128
returns `0xfffffffe` without changing output or workspace. Workspace demand
is the checked request length plus 32,768 bytes. Insufficient workspace returns
status 2 without changing it. The caller grows only the requested owned buffer
and preserves live workspace bytes on retry. The `history.v1` image profile
declares 128 MiB input/output and 256 MiB workspace; it is not a standalone
stdio or public protocol limit.

## Qualification

The registered native producer executes 1,992 independent inputs through the
shared map owner and the typed projection, retaining all 11,991 calls and all
665,635,980 bytes of input and before/after output/workspace records. The
34 boundary controls cover malformed framing, short output, exact growth,
capacity retries and dirty workspace reuse. Read-only evidence controls bind
the complete stream, actual requests, capacity continuation, case order and
source/build identities. A separate fresh locked Rust recipe executes the
unchanged target types and compares every admitted canonical map and entire
typed response frame. These are component contracts; public handler and whole
runtime activation remain false.
