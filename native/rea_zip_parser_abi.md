# HIA classic ZIP descriptor parser

`native/rea_zip_parser.hepta` owns classic ZIP directory parsing, all admitted
structural reads, declaration checks, filename roles, paging, SHA-256 directory
and EOCD commitments, descriptor observation tokens, error messages, and the
complete parser JSON result. Its entry is
`f0(source: readbuf, output: mutbuf, workspace: mutbuf) -> u32`.

The caller supplies one already admitted, read-only regular-file descriptor.
The descriptor remains open and identifies the same object for every read and
the final metadata observation. Descriptor numbers and paths are not accepted
from public JSON by this component. Root confinement, configuration authority,
public typed parameters, worker lifetime, cancellation, continuation identity
checks and optional whole-file hashing are separate integration responsibilities.

The Python author and the Rust/Python qualification transports are development
tools. They do not implement ZIP grammar or compute the native result. Every
format decision and every digest in that result is executed by the compiled
HIA image. The qualification transports only admit the source-bound image,
provide borrowed buffers, perform exact positional reads on the same descriptor,
and capture `fstat` metadata.

## Descriptor request

All words are unsigned 64-bit little-endian values. A request is exactly 120
bytes. Its first eight bytes are `HZIPRQ01`, followed by fourteen words:

| Offset | Value |
| --- | --- |
| 8 | Filter: 0 all, 1 manifest, 2 dex, 3 native_library, 4 resource, 5 java_class, 6 signature_marker |
| 16 | Zero-based selected entry offset |
| 24 | Page limit, 1 through 256 |
| 32 | Device |
| 40 | Inode |
| 48 | File size |
| 56 | File mode |
| 64 | Owner UID |
| 72 | Owner GID |
| 80 | Link count |
| 88 | Modification seconds, signed two's-complement bits |
| 96 | Modification nanoseconds |
| 104 | Change seconds, signed two's-complement bits |
| 112 | Change nanoseconds |

The metadata words are private file-owner observations, not caller-supplied
claims. HIA computes the original `afv1_` token from the exact colon-separated
metadata string. The complete request is retained privately and compared on
every continuation. Use a new zeroed workspace for a new descriptor operation.

The workspace minimum is 67,108,864 bytes. A complete maximum response buffer
is 1,048,616 bytes: the original 1 MiB worker payload bound plus a 40-byte frame.
The existing compiler input/image limit of 1 MiB remains unchanged. This module
fits it without increasing the compiler or generic transport limits.

## Native-owned effects

Return `0xfffffff0` means one effect is pending. The request at workspace offset
8192 is exactly ten words:

| Word | Value |
| --- | --- |
| 0 | Eight bytes `HZIPFX01` |
| 1 | Strictly increasing sequence, starting at 1 |
| 2 | Action 1: positional read; action 2: final descriptor metadata |
| 3 | File offset; zero for metadata |
| 4 | Exact requested length |
| 5 | Destination offset within the private workspace |
| 6 | Completion sequence, initially zero |
| 7 | Returned length, initially zero |
| 8 | Errno, initially zero |
| 9 | Reserved zero |

For action 1, the transport fills the requested destination from the same
descriptor. It may retry an interrupted syscall and finish a short syscall,
but it cannot select new ranges or alter the logical request. Physical chunks
are at most 65,536 bytes. HIA owns logical-read accounting and may split one
admitted read across multiple effects.

Action 2 requests exactly 88 bytes at workspace offset 9000. Those bytes are
the eleven metadata words in the descriptor request, in the same order.
HIA compares the complete original and final observations before publishing
success. A real modification produces the original `ensure_unchanged` error.

After filling bytes, the transport writes only completion words 6 through 9.
HIA checks sequence, action, range, destination, exact returned length and
reserved fields against its retained private state. The callback may not
rewrite phase, budget, request or result fields. Scratch and the effects are
private to the admitted operation; they do not confer file authority.

## Terminal response and refusal

A terminal return is the complete response extent. Its 40-byte header is
`HZIPRS01`, followed by status, error code, payload length and logical structure
read bytes. Status 0 has error code zero and a complete UTF-8 JSON payload.
Status 1 has a nonzero error code and the exact original parser error text.
JSON member order is not an external contract; all values, fields, nulls,
arrays, limits, roles and error strings are compared with the original parser.

Malformed input or private continuation state returns `0xffffffff`.
Insufficient borrowed capacity returns `0xfffffffe`. No pending effect or
partial report is a successful result. The result is constructed in private
memory and only copied to the output after checking its complete extent.

## Field grammar entry

`HZIPAT01` exposes the same field validators used by the complete parser. This
allows the unchanged original tests to call their original helper boundaries.
The 48-byte header contains operation, flags, method, payload offset and field
length, followed by exactly that many bytes, at most 65,535.

| Operation | Result |
| --- | --- |
| 1 | Complete list of admitted extra-field IDs |
| 2 | Decoded member name and original `ascii` or `utf8` encoding label |
| 3 | `null` after local-extra validation, including the original AAPT2 align32 rule |

These operations use the same response frame and error strings. They do not
read files, change parsing policy, or bypass validation in the directory path.

## Preserved format domain

The native implementation retains the original 50,000-entry count, 16 MiB
central-directory bound, 64 MiB logical structural I/O budget, 32 MiB retained
representation accounting, and 1 through 256 page limit. A regular file must
have an exact size from 22 through 2^53-1 bytes. It supports the original
classic ZIP, APK and JAR structural observations, including signed and
unsigned descriptors and narrowly defined AAPT2 local alignment padding.

It refuses ZIP64 and multi-volume declarations, prefixed or overlaid archives,
duplicate names, overlapping local ranges, inconsistent declarations, unknown
legacy non-ASCII filename encodings, invalid UTF-8, ambiguous paths and Unicode
path override fields. Central extras always retain strict TLV grammar.
Sorting and full-name comparisons handle the complete entry domain. Hash
table collisions compare all bytes and cannot merge different names.

The implementation does not decompress member payloads, validate payload CRCs,
verify signatures, or infer application identity from filename labels. Those
same limitations remain in the result. Bytes between local records and the
central directory remain uninterpreted as in the original parser.

The imported SHA-256 and UTF-8 functions are recorded in the composition file
with exact source hashes. Function names and direct-call targets are relocated;
their bodies remain identical. The native SHA append path copies raw selected
bytes into the imported compressor's private workspace. No host digest is used
for a product result.

## Qualification and integration scope

The retained original Rust parser and all eight original test methods run with
the original locked dependencies. The native binding then executes the same
test file and all its original assertions against the actual compiled HIA
entry, including helper tests, a sparse 40 MiB archive and a real AAPT2 APK.
Preparation failures are retained separately from actual product results.

The independent differential client compares complete JSON or exact error text
for every original fixture, every role filter, paging boundaries, all bytes of
the original small ZIP under three mutation masks, truncated records, path and
UTF-8 cases, descriptors, extras, a maximum EOCD comment and maximum variable
field lengths. The limit client executes the full 50,000-entry domain, 50,001
refusal, fixtures immediately below and above the original retained budget,
and a real metadata change before final observation. Full effect bytes and
terminal responses are retained with the original reference results.

Passing these parser gates does not qualify a public MCP route. Integration
must still provide the actual configured root owner and one held descriptor,
original public typed validation and identity checks, original isolation and
deadline behavior, rechecked directory commitments, optional full-file hash,
and the final public response bound. The composition record keeps those wider
claims false until their own complete original gates pass.
