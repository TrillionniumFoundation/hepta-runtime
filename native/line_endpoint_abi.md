# Native line endpoint parser

The `line_endpoint.hepta` owner dispatches retained and wide private frames
through `f0(readbuf, mutbuf, mutbuf) -> u32`. Both accept a 32-byte header and
an optional UTF-8 span. Every integer is little-endian u64. The retained
interface is:

| Offset | Field |
| ---: | --- |
| 0 | `HIAEP001` |
| 8 | Kind: 0 signed i64 bits, 1 other JSON number, 2 decoded string, 3 another canonical JSON Value |
| 16 | Payload byte length |
| 24 | Scalar bits for kind 0, otherwise zero |

Kinds 0 and 1 have no payload. Kinds 2 and 3 require complete valid UTF-8.
Eight scratch bytes suffice. The return is a complete result byte count,
`0xffffffff` for invalid input or scratch shorter than eight bytes, or
`0xfffffffe` for insufficient actual output or an unrepresentable success
byte count. Invalid input and short output preserve the output buffer.

The result starts with `HIAEPR01`, tag, value and auxiliary, all u64 words.
Tag 1 carries an i64 number's bits in value and zero auxiliary. Tag 2 carries
the nonzero line number and the two lowercase ASCII hash bytes in auxiliary's
low two bytes. Tag 0 carries the original error reason (1 through 7), exact
UTF-8 message length in auxiliary, then that message. Hashes are parsed but
do not constrain `view` range selection.

## Source domain and retained transport

The source entry has no fixed 8 MiB input-byte gate. Validation, Unicode
whitespace trimming and numeric scanning use full u64 offsets; they do not
pack a byte cursor and codepoint into two 32-bit halves. This matters when
the existing Value serializer expands a publicly admitted JSON number array
past the original frame window. The parser must preserve the entire original
diagnostic for that Value. Long strings consisting of whitespace or leading
zeroes can also still produce a small successful number result.

`line_endpoint_composition.json` binds every current function AST and the
exact relocation of the retained entry from `f0` to `f18`. The seventeen
existing helpers remain unchanged. Signed parsing, unsigned line IDs, Unicode
whitespace membership, UTF-8 validation, exact messages and hash spelling
retain their admitted behavior. Diagnostic length arithmetic is checked
before output; the reserved u32 return-code range begins at `0xffff0000`.

The standard standalone loader's 8 MiB input/output window is unchanged.
That transport allocation is distinct from the source domain. The actual
`view_call` composition passes its admitted, growing caller-owned frame
directly to this same source image and grows the endpoint output when the
image returns a genuine output-capacity refusal. It imposes no fixed number
of those growth steps. Available memory and the ABI's representable result
extent remain real resource constraints for that retained interface.

## Wide private result

`HIAEP002` uses the same input fields and type rules. The result magic is
`HIAEPR02`; tag, value, auxiliary and diagnostic payload retain their meanings.
A completed call returns exactly 32. The complete result extent is 32 plus
the diagnostic length for tag 0, or 32 for tags 1 and 2. The caller reads that
u64 extent from the admitted header and validates it against the actual output
allocation; it does not interpret the u32 return as the payload length.

If a diagnostic needs a larger output and at least 32 output bytes are
available, the owner returns `0xffffffd0` and writes `HGRWS002`, kind 2, the
complete required u64 output capacity, and zero. This is a growth request,
not a typed error. An output shorter than 32 bytes still returns
`0xfffffffe` without changing output. An unrepresentable extent returns
`0xfffffffc`. The wide bridge grows the actual allocation and retries this
pure parser. The retained `HIAEP001` entry continues to use its original
capacity and result-length convention.
