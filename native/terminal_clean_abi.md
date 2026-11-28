# Terminal output cleaning

`terminal_clean.hepta` implements the complete deterministic byte result of
`src/mcp/fs/shell.rs::clean_terminal_noise`, including the original ANSI regular
expression and `flush_repeats`. It does not spawn a shell, read an environment,
own child processes, choose a workdir or register a production MCP handler.

The implementation is HIA `hepta.hia.program.v8`, using the repository's pinned
Linux x86-64 compiler. The source contains all semantic operations. The emitted
machine code has no regex library, interpreter or original Rust implementation
as a runtime dependency. Original Rust remains an independent qualification
reference until the production shell owner is replaced and qualified.

## Entry and result

`f0(readbuf input, mutbuf output, mutbuf workspace) -> u32` uses the existing
three-buffer, disjoint borrowed-byte ABI. The input is the complete UTF-8 shell
output string, without a header, terminator or length field. A successful result
is the number of result bytes written at output offset zero. Only that prefix is
written; bytes beyond it are unchanged. Empty input returns zero and requires no
workspace or output capacity.

| Return | Meaning |
| --- | --- |
| `0..0xfffffffd` | Complete UTF-8 result length |
| `0xffffffff` | Input is not a complete valid UTF-8 string |
| `0xfffffffe` | Workspace, output or representable result-length capacity is insufficient |

The complete input is validated before workspace-capacity admission. Both
rejection results leave the **entire output buffer unchanged**. Workspace is
private scratch; it may change after a capacity rejection. There is no retained
state between calls, no total input-length policy and no silently truncated
output. The ordinary executable transport has its separately declared buffer
capacities; they do not change this component's semantics.

The first `input.len()` workspace bytes hold ANSI-stripped text and then its
in-place line-normalized form. The following bytes hold the complete joined
result before its final trim. Required workspace is therefore
`input.len() + joined_result.len()`, where `joined_result` includes repeated-line
markers and any leading or trailing blank lines. This intermediate capacity is
checked separately from final output capacity. Markers for short repeated lines
can make the result longer than the original input. Final output admission
occurs only after leading LF and trailing Unicode whitespace have been removed.

## Preserved behavior

The ANSI matcher preserves the existing regular expression's alternatives and
priority. A CSI consumes its valid parameter/intermediate/final sequence. An
incomplete CSI falls back to consuming ESC plus the following `[` scalar. An
OSC consumes all following non-BEL/non-ESC characters, including line breaks,
and may consume BEL or ESC followed by a backslash as its optional terminator.
An unfinished OSC still consumes its matched prefix. The final ESC alternative
consumes exactly one Unicode scalar other than LF. A trailing ESC or ESC before
LF is unmatched in this stage; subsequent control-character filtering handles
it. This preserves original regex behavior rather than substituting a different
terminal parser.

After stripping escapes, each LF-delimited line has one trailing CR removed;
only the frame after its final remaining CR survives. Backspace removes one
previous Unicode scalar within that frame. Other Unicode `Cc` controls are
discarded, except TAB. Trailing Unicode `White_Space` characters are removed
from each line. Leading spaces and all other non-control scalars are preserved.

Empty lines never participate in duplicate collapsing. Two identical adjacent
nonempty lines remain verbatim. Three or more become one line followed by
`[... last line repeated N more times]`, where `N` is the count after the first
line. The final joined result loses only leading LF characters and trailing
Unicode whitespace. Decimal counts use the full original LP64 count domain.

## Source map

| Functions | Owner |
| --- | --- |
| `f0` | Entry validation, scratch admission and successful output publication |
| `f1`, `f2` | Complete UTF-8 validation and scalar decoding |
| `f3`–`f5` | Unicode whitespace, previous scalar and trailing trim |
| `f6`, `f7` | Original ANSI matching and replacement |
| `f8`–`f10` | LF boundaries, final CR frame and in-place line cleaning |
| `f11`, `f12` | Exact adjacent-line comparison and repeat count |
| `f13`, `f14` | Capacity-checked line joining and duplicate collapse |
| `f15`, `f16` | Decimal count length and exact repeat-marker publication |

The module is an internal pure owner. Its qualification does not qualify shell
spawn, process-group ownership, cancellation, background promotion, durable job
output or production routing, and does not authorize deleting their old owners.
