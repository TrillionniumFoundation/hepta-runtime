# Native regex error formatting

`view_regex_diagnostic.hepta` owns the complete UTF-8 display bytes for a
validated regex error descriptor. It is a pure borrowed-byte function with no
workspace writes and no host formatter. The raw view-regex owner adds the
original `Invalid regex pattern: ` prefix.

The input is `HVRGE001` followed by nine little-endian u64 words: error kind,
pattern length, primary start, primary end, auxiliary-present, auxiliary
start, auxiliary end, numeric limit, reserved zero. The complete pattern starts
at offset 80. Span endpoints are UTF-8 boundaries in the original pattern.
Kinds 1 through 34 and 40 through 46 are the source-owned syntax/HIR errors;
kind 64 is the compiled-size error and has an empty pattern and zero spans.
Kind 24 carries the u32 parser nest limit. Other syntax/HIR kinds require
limit zero. Only kinds 14, 15 and 18 admit a second source span.

The output is raw UTF-8, exactly the original single-line or multiline regex
display, including scalar columns, CRLF treatment, line numbers, primary and
auxiliary carets, trailing error text and numeric limits. The owner performs
a complete measurement pass and all validation before writing any output.
An invalid frame returns 0xffffffff. An insufficient output capacity or an
unrepresentable u32 return extent returns 0xfffffffe without changing output.
Successful return is the exact byte length. Empty workspace is permitted.

`HRGAST01` and `HRGTRE01` retain their existing error and payload contract.
The new private `HRGAST02` mode 2 request enables source spans. Its successful
`HRGTRE02` result contains a 64-byte header, the existing 64-byte AST nodes and
pool, one 32-byte diagnostic-span record per node, and the complete original
pattern. HIR consumes this private form and produces either its existing HIR
result or `HVRGE001`. The configuration controller keeps its original
anchored legacy protocol.

The exact kinds, messages and span-selection functions are defined in HIA.
Validation compares complete real Regex/regex-syntax error strings from the
locked original dependency versions; it does not use Python-created expected
messages. The finite current parser/compiler/resource profile remains
explicit and does not establish all-input or whole-runtime closure.
