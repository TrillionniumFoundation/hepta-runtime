# Native file version codec

`stat_version.hepta` implements the exact five-field version string emitted by
the original `src/mcp/runtime/binary_file.py:version` and its canonical inverse.
It converts raw stat words without multiplying signed seconds by one billion
in a fixed-width integer. Negative times and the complete signed 64-bit seconds
domain therefore retain the original Python arbitrary-precision result.

The entry is `f0(readbuf input, mutbuf output, mutbuf workspace) -> u32`.
The input and output must be disjoint; workspace is private and at least 256
bytes. Input has the ordinary 8 MiB runtime bound. Every integer in the packet
is an unsigned little-endian 64-bit word; timestamp seconds use their signed
64-bit two's-complement representation.

## Packet and operations

The first eight bytes are ASCII `HSTVER01`; the next eight bytes select the
operation. No trailing bytes are permitted for operation 1.

| Operation | Bytes after the 16-byte header | Successful output |
| --- | --- | --- |
| 1 | Exactly seven words: device, inode, size, modification seconds, modification nanoseconds, change seconds, change nanoseconds | ASCII `device:inode:size:mtime_ns:ctime_ns` |
| 2 | The complete version string, without a terminator | The seven words in the same order, exactly 56 bytes |

Device, inode and size cover the full unsigned 64-bit domain. Each seconds
field covers the full signed 64-bit domain. Each fractional nanosecond field
must be in `[0, 999999999]`. Formatting uses the original mathematical value
`seconds * 1000000000 + nanoseconds`, with no leading zeroes, no positive sign,
and one minus sign for negative values. The complete string is at most 122 bytes.

The inverse accepts exactly strings the formatter can produce. Empty fields,
extra separators, whitespace, positive signs, negative zero, leading zeroes,
non-ASCII digits, exponents, embedded NULs and values outside the stat domain
are refused. Its accepted representation is bijective: reformatting the seven
returned words reproduces the supplied bytes exactly.

## Status and atomicity

Success returns the number of initialized output bytes. Refusals leave the
entire caller output unchanged; workspace is scratch and may have changed.

| Status | Meaning |
| --- | --- |
| `0xffffffff` | Malformed envelope, unknown operation, wrong operation-1 size or invalid fractional nanoseconds |
| `0xfffffffe` | Insufficient output or workspace capacity |
| `0xfffffffd` | Operation-2 text is noncanonical or outside the stat domain |

Input size is checked first, followed by workspace capacity, magic and the
selected operation. Domain checks precede output-capacity checks. Formatting
and parsing finish in private workspace before publishing any output bytes.

## Use by a file-read owner

The original `expected_version` parameter is an optional decoded JSON string.
A caller must not normalize it. An accepted operation-2 result can be compared
with the file's seven stat words. A noncanonical string is a guaranteed version
mismatch, but that mismatch must be reported at the original comparison point:
after opening and admitting a regular file and before offset checks or reading.
It must not hide an earlier missing-file or path-admission error.

This component performs no filesystem operation, config lookup or MCP dispatch.
It does not replace `binary_read` by itself. It preserves the original version
representation and supplies a lossless boundary to the native I/O owner.

## Executed qualification

`tests/hia_native/test_stat_version.py` extracts the unchanged original Python
function from its hash-pinned source with Python's AST reader and calls that
function directly. It does not substitute a newly written formatting oracle.
The suite compares 5,236 native formatting results and 5,236 inverse roundtrips,
including 5,000 deterministic random full-domain cases, integer extrema, negative
times and stat records from real files. It also checks 66 noncanonical strings,
78 malformed frames, five capacity controls, eight independent HIA VM cases and
three standalone ELF executions with an empty `PATH`.

The native-call count is 10,624. VM and standalone process observations are
reported separately. The inverse reference uses Python arbitrary-precision
integers and requires an exact roundtrip through the unchanged original
formatter. The retained corpus and observed compiler/image identities are
recorded in `stat_version_original_python_comparison.json`.
