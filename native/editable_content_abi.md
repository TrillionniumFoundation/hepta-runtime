# Editable content byte owner

`editable_content.hepta` implements the original `EditableContent` methods from
`src/mcp/fs/text_editing.rs`: construction, normalized and rendered bytes,
insertion after `incoming_content_lines`, replacement by normalized UTF-8 byte
offsets, and trailing-newline preservation. The original source file is pinned
by Git blob and SHA256 in `editable_content_composition.json`.

This internal component produces an edit result. File access, canonical-path
locks, atomic writes, undo history, view-cache updates, line-ID validation,
high-level replacement matching and production tool dispatch remain separate
owners. It does not advertise a public MCP tool.

## Entry and limits

The entry is `f0(readbuf input, mutbuf output, mutbuf workspace) -> u32` on Linux
x86-64. The ordinary module and static filter declare 8 MiB input, 8 MiB output
and 32 MiB workspace capacities. These are component transport limits; no
unbounded original handler parity is asserted. Qualification includes complete
5 MiB files, a 5,242,880-line input, mixed CRLF/LF, and UTF-8 boundaries.

Workspace uses 256 header bytes and four byte arrays. Its normalized-content
capacity is `floor((workspace_bytes - 256) / 4)`. At least 260 workspace bytes
are required. The byte arrays retain the normalized text and the ending of
each line, plus a private staging pair. A separate state bit retains a final
empty line with no terminator; that line is distinct from an empty line vector.

`0xffffffff` refuses a malformed typed frame or invalid UTF-8. `0xfffffffe`
refuses a declared workspace or output capacity. Both leave the entire caller
output unchanged. A method-level error is a normal structured response carrying
the state produced by earlier successful operations and the exact original
error text. No filesystem effects occur. No whole-process memory-erasure claim
is made for this text component.

## Request

All integers are unsigned 64-bit little endian. The fixed header is 48 bytes.

| Offset | Field |
| --- | --- |
| 0 | Eight bytes `HEDIT001` |
| 8 | Output mode: 0 rendered bytes, 1 normalized bytes |
| 16 | Initial raw UTF-8 byte length |
| 24 | Number of ordered operations |
| 32 | Reserved, zero |
| 40 | Reserved, zero |
| 48 | Initial raw bytes, then the operation records |

Each operation has four words: operation, `a`, `b`, and payload byte length,
followed immediately by its UTF-8 payload. No padding or trailing bytes are
permitted. The entire frame, including later operations, is structurally
validated before the initial text state is constructed.

| Operation | `a` | `b` | Payload and original method |
| --- | --- | --- | --- |
| 1 | Zero-based insertion position among `EditableLine` records | Trailing-newline flag, exactly 0 or 1 | Text is split using the original incoming-content line semantics; all trailing CR bytes are removed from each incoming line, then `insert_lines` runs |
| 2 | Start normalized byte offset | End normalized byte offset, exclusive | Passed to `replace_normalized_range` without additional sanitation; both offsets must be UTF-8 character boundaries |
| 3 | Zero | Zero | Empty payload; `preserve_trailing_newline` |

Zero operations returns the initial state. There is no independent operation
count ceiling: every record must fit the admitted input. On a method error,
later operations do not run. Successful operations before that error remain
represented in the response.

## Response

The response header is 80 bytes, followed by the selected text bytes and then
the UTF-8 error message. Success has no error-message bytes.

| Offset | Field |
| --- | --- |
| 0 | Eight bytes `HEDRES01` |
| 8 | Method status: 0 success, 1 error |
| 16 | Count of successfully completed operations |
| 24 | Original dominant ending length: 1 for LF, 2 for CRLF |
| 32 | Original `had_trailing_newline` state, 0 or 1 |
| 40 | Number of actual `EditableLine` records |
| 48 | Normalized UTF-8 byte length |
| 56 | Rendered UTF-8 byte length |
| 64 | Selected text byte length |
| 72 | Error-message byte length |
| 80 | Selected text, followed by error text |

The complete output length is admitted before any output byte is written.
Unused output bytes remain unchanged.

## Preserved behavior

Construction removes exactly one CR immediately before each LF into the line's
CRLF ending. Other CR bytes remain text. CRLF wins as the dominant ending only
when its count strictly exceeds the LF count; a tie selects LF. Untouched lines
keep their own endings. Changed replacement regions use the original dominant
ending, including the original rule for joining a changed tail to its suffix.

Inserting no lines leaves the stored trailing-newline state unchanged. Other
insertions update it from the supplied flag, even for an insertion in the
middle. Replacement does not update that flag. Preservation retains an empty
last line's terminator when stripping it would delete the blank line itself.

The four UTF-8 and integer byte helpers are exact function-graph imports from
the already qualified `text_budget.hepta`; only function names and direct-call
targets are relocated. Their original function hashes and relocation mapping
are recorded in the source-composition file.

## Qualification

The native test captures 8,749 requests for the unchanged original Rust owner:
92 roundtrips, 4,564 insert/preserve cases, 2,242 replacement/preserve cases,
368 full-u64 errors, 80 empty-unterminated-line sequences, 1,400 deterministic
random sequences and three complete large-file cases. The original methods
produce byte-identical complete responses for every captured request.

Separate native-only controls include 65 malformed-frame refusals, four
capacity refusals, one exact-output-capacity acceptance, and four static ELF
executions with an unusable executable search path. The ELF controls include the
complete 5,242,880-line case and exact binding of the static transport prefix to
the admitted compiled HIA image. Original Rust replay does not add native
coverage or establish production call-site replacement.
