# HIA runtime byte kernels

`runtime_bytes.hepta` implements the runtime's deterministic line identifiers,
line range resolution, log page planning, and scalar identity predicates in HIA.
The compiled `f0` entry executes native machine instructions. No Rust, Python,
shell, dynamic library, subprocess, or interpreter is called by this module.
The build driver and independent differential tests remain host tools.

## Original semantics

The comparison baseline is `TrillionniumFoundation/hepta-runtime` commit
`a0dcdda1991ec536d5e2d252c006a778993fa566` (tree
`98d96c88d54082637c27f1cbfae61a66d0dd81e7`).

| Original path | Git blob | Implemented operation |
| --- | --- | --- |
| `src/utils/line_hash.rs` | `0e521656ba24869dbc05afc51d62aa4af79b5e44` | FNV-1a line hash; composite line ID; strict/clamped index resolution |
| `src/mcp/runtime/jobs.rs` | `7b9ca9d1c00f31411265c1dc26a18ead79907ec9` | `READ_CODE` cursor and page-size arithmetic |
| `src/mcp/runtime/config.rs` | `e55d9f536c069b7612f7a7cf81e691fd2394439c` | `valid_name` |
| `src/mcp/runtime/execution.rs` | `541d7bf2ee069ae082b01ac10e0b1ed215927683` | `valid_digest` and `valid_text` |

The Rust oracle copies the line/hash/index functions and identity predicates
from those sources without editing their bodies. Its framing adapter and log
page arithmetic are test code. The Python differential reference uses a separate
FNV fold formulation and covers malformed frames, capacity, scalar boundaries,
and randomized values. Tests can export a compressed binary corpus for the
standalone Rust oracle; comparing its output against the retained native output
checks the exact original Rust functions without Cargo dependencies.

## ABI and framing

Target: Linux x86-64 LP64. HIA entry:

```text
f0(input: readbuf, output: mutbuf, workspace: mutbuf) -> u32
```

The machine ABI is six arguments: input pointer/length, output pointer/capacity,
workspace pointer/capacity. Buffers must be distinct, live for the call, and
consistent with their declared lengths. This module does not use or change the
workspace. Successful calls return the initialized output length; error codes
are reserved at the top of the u32 range. Input and output length bounds imposed
by the native image loader also apply.

Every input begins with this 40-byte header; all integer words are little-endian:

| Offset | Width | Field |
| --- | --- | --- |
| 0 | 8 | ASCII `HRTKERN1` |
| 8 | 8 | Operation number |
| 16 | 8 | `a` |
| 24 | 8 | `b` |
| 32 | 8 | `c` |
| 40 | remaining | Byte payload, when allowed |

Unused header words must be zero. Numeric operations 3, 4, and 5 require exactly
40 input bytes. Unknown operations, a changed magic, short input, nonzero unused
words, or extra numeric input return `INVALID_FRAME`. No output is written before
framing and operation-specific capacity checks succeed. Domain failures and
capacity failures leave the complete output buffer unchanged.

## Operations

| Op | Inputs | Output |
| --- | --- | --- |
| 1 | `a=b=c=0`; line bytes in payload | Two lowercase ASCII hex bytes |
| 2 | `a=line_number`, `b=c=0`; line bytes in payload | Decimal line number, `:`, two hex bytes |
| 3 | `a=i64 index` encoded as two's-complement bits; `b=u64 total_lines`; `c=0` | Two u64 words: resolved one-based index, zero |
| 4 | Same as op 3 | Two u64 words: resolved index, `was_clamped` (0 or 1) |
| 5 | `a=u64 offset`; `b=u64 observed_size`; `c=u64 requested_limit` | Four u64 words: planned count, next offset, EOF (0 or 1), effective limit |
| 6 | `a=b=c=0`; name in payload | One byte, 0 or 1 |
| 7 | `a=b=c=0`; digest in payload | One byte, 0 or 1 |
| 8 | `a=b=c=0`; identity text in payload | One byte, 0 or 1 |

### Line hash and ID

The hash starts at `2166136261`; each byte is XORed into the 32-bit state followed
by multiplication by `16777619`, wrapping at 32 bits. The state is folded with
XOR from 32 to 16 to 8 bits. The result uses exactly two lowercase hexadecimal
digits, including leading zeroes. The original API accepts a Rust `str`; its
equivalence domain is UTF-8 text encoded as bytes. The native arithmetic also
accepts arbitrary byte sequences, which differential tests identify separately
from the original text domain.

Operation 2 preserves the original `line_id` formatting for every LP64 `usize`,
including zero. The existing caller decides whether a line number is a valid
one-based target. Content is hashed without trimming or newline normalization.
Empty input hashes to `c5`; `hello` hashes to `57`; `hello world` hashes to `c6`.

### Line index resolution

Zero is always an error. Positive indices are one-based. Negative indices count
backward from the end, with -1 selecting the last line. Strict mode rejects an
out-of-range index. Clamped mode uses `total_lines` for a positive overshoot and
1 for a negative overshoot. This preserves the original empty-file behavior:
positive overshoot returns `(0,true)`, negative overshoot returns `(1,true)`.

The original `checked_neg` maps `i64::MIN` to `usize::MAX`; the native module
preserves that exact rule. For example, `i64::MIN` with `total_lines=u64::MAX`
resolves to `(1,false)`, whereas smaller totals reject or clamp. No signed
negation overflow or `offset+count` overflow is used to implement these cases.

### Log page planning

An offset beyond the observed size is an error and never silently rewinds.
The effective limit is `max(1,min(requested_limit,16384))`. Planned count is the
lesser of that limit and `size-offset`; next offset is `offset+count`; EOF means
next offset equals size. An absent caller limit must be resolved to 16384 by
the protocol adapter before invoking this operation.

This operation plans a read against an observed size. The caller still owns
the original descriptor, actual read result, inode/link checks and durable job
identity. A short physical read advances by its actual byte count, as in the
original `READ_CODE`; the planned count alone is not an observation of bytes.

### Identity predicates

Operation 6 exactly accepts 1–128 ASCII bytes from `A-Z a-z 0-9 . _ - @`.
Operation 7 accepts exactly 64 lowercase hex bytes with at least one byte
different from `0`. Operation 8 accepts 1–256 ASCII graphic bytes (33 through
126 inclusive). Unicode letters, whitespace and non-ASCII bytes do not become
ASCII through normalization. These are syntax predicates; the runtime's other
host, path, ownership and authorization checks remain required by their callers.

## Error values

| u32 value | Name | Meaning |
| --- | --- | --- |
| `0xffffffff` | `INVALID_FRAME` | Invalid framing, operation, unused word or numeric payload |
| `0xfffffffe` | `OUTPUT_CAPACITY` | Output capacity is smaller than the complete result |
| `0xfffffffd` | `ZERO_LINE_INDEX` | Index zero in strict or clamped mode |
| `0xfffffffc` | `POSITIVE_LINE_RANGE` | Strict positive index exceeds total |
| `0xfffffffb` | `NEGATIVE_LINE_RANGE` | Strict negative index exceeds total |
| `0xfffffffa` | `CURSOR_RANGE` | Log cursor exceeds observed size |

Framing is validated first. Numeric domain errors precede capacity checks;
otherwise the capacity check precedes output writes. A false identity predicate
is a successful one-byte result, not an error.

## Boundary of this module

This module supplies deterministic functions to the runtime migration. It does
not implement endpoint JSON parsing, stale-ID relocation/error prose, filesystem
I/O, MCP, HTTP, SSH, persistent job ownership, or REA. Those remain separate
functional families in the migration inventory. Replacing these numerical
functions does not retire their surrounding services or their acceptance tests.
