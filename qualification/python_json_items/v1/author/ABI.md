# HIA JSON object item extraction

This component serves the inode metadata owner. It parses a complete JSON value and
returns every dictionary item in Python insertion order. Repeated decoded keys keep
the last value and the first key position. Keys preserve all Unicode code points,
including lone surrogates. No host interpreter supplies parsed values or traversal.

The input is the existing 64-byte HPYJSQ01 command 1 packet: primary UTF-32LE code
point count at 16, auxiliary count 0 at 24, explicit parse budget at 32, nonzero
dump-budget reservation at 40, zero at 48, and payload byte count at 56. The
complete UTF-32LE primary starts at 64. Count is at most 8,388,608; budgets are
1..20,000. The calling CPython 3.12.3 Linux profile fixes parse budget 9,997.
Work is at least 16,480 + 40 * count bytes. Values above U+10FFFF are invalid.

Return values are actual full response extents, or u32 -1 invalid, -3 insufficient
work, -2 insufficient output. Admission refusals leave work and output unchanged;
later insufficient-output refusals leave output unchanged and work is scratch.
Input bytes and bytes beyond the supplied output/work extents are unchanged.

Success has a 64-byte HPYJIR01 header: kind 0 at 8, tag 7 at 16, dictionary truth
at 24, zero at 32, item count at 40, zero at 48, total payload bytes at 56.
Each item is key code point count (u64), full value record extent (u64), complete
decoded key UTF-32LE, then a complete HPYJSR01 kind-0 typed value record. Nested
container values contain their full original UTF-32LE lexical span, with the
existing value ABI's scalar tags, integer bytes, float bits, truth and encodings.
The item stream contains no padding or omitted members.

Syntax, integer-digit and recursion failures use the existing HPYJSR01 kind-3
diagnostic. A parsed non-dictionary produces kind-3 diagnostic code 22 with the
complete AttributeError prefix and the original type's missing items message.
The caller can wrap these unchanged UTF-8 bytes in HCPER001.

The author retains the exact reachable HIA function IR from JSON value V2
e0a7b74a760d501f0c0ad987ec7bded12ed3ee3d and its raw composition
c4025871dd242eb282135b76d65188f7b4001813. Inverse relocation must recover every
retained original function. This is a new separate image; it does not alter the
qualified JSON value commands 1 through 6 or their image.

The complete original/native domain must cover item order, overwritten keys and
first insertion positions, escaped aliases, non-ASCII and surrogate keys, every
scalar type and nested value extent, wide dictionaries, all parser errors reached
by this API, non-dictionary AttributeError, and exact buffer/refusal behavior.
This source author checkpoint records no application qualification.
