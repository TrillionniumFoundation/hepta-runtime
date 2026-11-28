# Native ASAR parser and selected-member verification

`native/rea_asar_parser.hepta` implements the original canonical Electron ASAR
Pickle/header grammar and selected-member verification in HIA. The native entry
is `f0(readbuf input, mutbuf output, mutbuf workspace) -> u32`.

The caller owns configured-root authorization, a single admitted regular-file
descriptor, process isolation, deadlines, cancellation and public response
publication. The descriptor must remain held throughout all continuations. A
request cannot supply a raw descriptor or manufacture a trusted metadata tuple.
The private metadata input is populated by the descriptor owner after admission.
This parser does not itself register an MCP tool or replace those owners.

## Buffers and lifecycle

Each operation starts with a fresh zeroed 256 MiB workspace. Output capacity is
4 MiB plus the 32-byte binary envelope. The input is a separate immutable span;
it must not alias either mutable buffer. A completed operation is terminal and
must not be replayed on the same workspace. Allocate the complete output span
before starting; an output-capacity refusal is terminal for that operation.

| Return | Meaning |
| --- | --- |
| `0xfffffff0` | One descriptor effect is pending. |
| `0xffffffff` | Invalid private frame, sequence or lifecycle. |
| `0xfffffffe` | Insufficient caller-provided buffer capacity. |
| `32..4194336` | Complete `HSARRS01` response extent. |

The compiler input and emitted image limits remain the existing 1 MiB. The
`history.v1` build profile supplies the existing 256 MiB workspace. The original
16 MiB header, 50,000 entries, directory depth 32, 4,096-byte member paths,
200,000 total integrity declarations, 64 MiB whole-member verification,
1 MiB internal selected-byte capture and 4 MiB worker JSON bounds are retained.
Public member reads keep their separate 65,536-byte limit.

## Initial request

All integers are little-endian u64 words. The initial frame is exactly 136 bytes
plus `member_length` UTF-8 bytes:

| Offset | Field |
| --- | --- |
| 0 | Eight ASCII bytes `HSARRQ01`. |
| 8 | Operation: 1 index, 2 read selected packed member. |
| 16 | Index offset or selected-member byte offset. |
| 24 | Index page limit or selected-byte length. |
| 32 | `require_complete`, exactly 0 or 1. |
| 40 | Member UTF-8 byte length. |
| 48 | Eleven private descriptor metadata words. |
| 136 | Exact member UTF-8 bytes, without a trailing NUL. |

The metadata words are device, inode, size, mode, uid, gid, link count, mtime
seconds bits, mtime nanoseconds, ctime seconds bits and ctime nanoseconds. Signed
seconds retain their two's-complement u64 representation. Atime is excluded.
HIA computes the original `asv1_` observation token from those exact values.

An index has an empty member, `require_complete=0`, limit 1..256 and offset at
most 50,000. A read validates the original relative POSIX member path, length
1..1,048,576 and offset at most 67,108,864. Complete-source acquisition requires
offset zero and refuses a selected member larger than the capture length.

## Pending effects

On pending return the workspace at byte 65,536 contains five u64 words:

| Word | Meaning |
| --- | --- |
| 0 | Eight ASCII bytes `HSARFX01`. |
| 1 | Strictly increasing operation-local sequence, beginning at one. |
| 2 | Action 1: positional read; action 2: descriptor metadata. |
| 3 | File byte offset; zero for metadata. |
| 4 | Exact requested byte count. |

The mechanical descriptor owner performs only the named operation on the same
held descriptor. It may assemble a header read from positional reads of at most
65,536 bytes; all member-content reads are already bounded to that chunk size.
A metadata request requires exactly 88 bytes, encoded as the same eleven words.

Each continuation supplies a new immutable input frame: eight bytes `HSARIN01`,
the requested sequence, returned byte count, positive errno (zero on success),
then exactly the returned bytes. Its fixed header is 32 bytes. The parser refuses
wrong sequences, oversized data and inconsistent frame extents. A short read or
nonzero errno yields the original phase-specific refusal. The completion does
not write private parser workspace directly.

HIA requests the 16-byte prefix, the complete remaining Pickle header, any
selected member chunks and a final descriptor metadata observation. It compares
all eleven initial/final metadata words before emitting success. Header identity
covers the complete original `[0, payload_offset)` bytes, including both Pickles
and zero padding. Whole-member and declared block hashes must agree before any
selected bytes are released; unselected payloads and unpacked sidecars remain
unverified, as in the original contract.

## Response

The envelope contains `HSARRS01`, status (zero success or one failure), internal
error code and exact payload byte length. The payload is UTF-8 JSON on success
and the original error text on failure. Success requires error code zero;
failure requires a nonzero error code. The generated composition lists the
stable error mapping.

The full JSON preserves request fields, source observation/header commitment,
complete inventory counts and coverage, page or member results, integrity
qualifications and all original limitation strings. Descriptor observations and
self-declared integrity do not authenticate a publisher.

## Source ownership and verification

The grammar, decoded-key duplicate rejection, exact numeric classification,
inventory validation, path ordering, range checks, SHA-256, integrity decisions
and result serialization execute inside HIA. The private SHA compressor uses
the bounded scalar schedule and rounds recorded in the composition. Imported
initialization, finalization, UTF-8 and numeric functions preserve their original
bodies, with function names and direct-call targets relocated. Complete private
state comparisons bind the SHA changes to the retained implementation.
The generic JSON parser does not reinterpret private serde marker object keys.

## Explicit HIA native lowering stage

`scripts/build_rea_asar_component.py` first compiles the parser and the separate
`native/rea_asar_private_lowering.hepta` stage with the unchanged pinned B3.
The stage accepts `HSHX6402`, the exact base-image length, and the complete base
image. It verifies the whole base image's SHA-256 before producing any output.
The binding records the complete parser source, compiler, function IR, observed
native layout, and original instruction bodies.

The stage generates scalar x86-64 instructions for private compressor `f65`
and the four little-endian word helpers `f63`, `f64`, `f75`, and `f76`. No optional
instruction-set extension or host cryptographic implementation is required.
Every other base-image byte is copied unchanged. Each replaced entry has an
explicit jump to appended HIA-generated code. A compression view shorter than
1,184 bytes, or a word access outside a complete in-view eight-byte range, runs
the original complete prologue and unchanged continuation. This preserves
original traps and partial writes. The private buffer, argument cells, and
result cell are disjoint and exclusively owned during a call.

The final manifest explicitly records this additional stage and marks the image
as an explicit HIA lowering product. It is not labeled direct B3 output and does
not inherit Hepta's whole-source cold qualification. The reproducible final
image is 549,750 bytes, SHA-256
`d5b57ebd0fe6956464cc95b5712449d543e3af5850442ae67d57049f5ef6fbd5`.

The retained complete component proofs cover all nine original native-bound
parser methods, 701 full-result/error comparisons, 12 original-limit comparisons
and a real same-descriptor mutation, 174 borrowed-buffer controls, 226 complete
SHA states and 14 independent digest vectors. The lowering also has full-state
compression and word-access comparisons, short/overflow behavior, callee-saved
register and stack checks. Four large-file cases run under the original worker
CPU, address-space, file-size, descriptor and wall limits. These are component
and resource proofs; the actual public worker/parent owners remain separately
qualified.

`tests/hia_native/rea_asar` contains qualification clients only. Its Rust fixture
binding retains all nine original parser test methods and all their assertions;
the native adapter transports exact metadata/read bytes and calls the actual
native image. The separate original oracle retains original parser and unique
JSON visitor bodies and exact original dependency versions/checksums. Python is
used for development, fixture construction and evidence capture, not for parser
or public product semantics.

Complete original and differential proof is recorded separately. Component
proof does not imply configured-host authorization, public identity pinning,
parent-side commitment rehashing, worker deadline, cancellation or MCP closure.
