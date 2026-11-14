# Request hint response composition

`response_hints.hepta` implements the byte-preserving response formatting in
`src/mcp/server.rs::append_hints`. It consumes the complete private hint-list
response from `request_context.hepta`. The request owner performs insertion-order
deduplication and draining; this component formats exactly the list it receives.
Its output is ordinary UTF-8 text, not an authority or session capability.

## Original behavior

An empty hint list returns the original result unchanged. A nonempty list adds
two LF bytes after the original result. Every hint then adds the seven UTF-8 bytes
for `⚠️ `, the complete hint bytes, and one LF. Empty strings, NUL, CR, LF,
trailing whitespace and the Unicode variation selector are preserved. The
composer does not trim, normalize, escape, truncate or deduplicate. In
particular, an empty hint still produces a warning line, and two equal hints in
an explicitly supplied list produce two lines. Normal request-owner composition
supplies the already deduplicated list.

The original call sites invoke `append_hints` after successful tool execution
inside `with_request_context`; errors leave via `?` and destroy the request
scope. This pure component does not reproduce scope creation, drain mutation,
task-local selection or the session view-cache capability. Those remain owned by
the request controller. A complete production caller must retain the private
drained bytes until successful publication, and reserve output before committing
an irreversible state transition. A plain public frame must not select another
request's state or cache.

## Borrowed-byte ABI

The entry is `f0(readbuf, mutbuf, mutbuf) -> u32`. All lengths and fields below
are unsigned little-endian 64-bit words. Buffers are nonaliasing, as required by
the existing borrowed-byte caller contract.

| Input field | Offset | Meaning |
|---|---:|---|
| `HRHAQ001` | 0 | Exact eight-byte composer magic |
| `base_length` | 8 | Length of the base result |
| `drain_length` | 16 | Length of the complete following request-owner response |
| reserved | 24 | Must be zero |
| base | 32 | Exactly `base_length` UTF-8 bytes |
| drain response | `32 + base_length` | Exactly `drain_length` bytes |

The drain response is the existing `HRCXR001` format: eight-byte magic, tag `1`,
hint count, payload byte length, then the complete payload. Each hint is an
eight-byte length followed by that many UTF-8 bytes. A zero-count response must
have an empty payload. No unused bytes, truncated words or trailing bytes are
admitted. The composer accepts the same bytes returned by both DRAIN and PEEK;
the caller is responsible for choosing the correct request-owner operation.

Return values:

| Return | Meaning | Output and workspace |
|---|---|---|
| `0 .. 0xfffeffff` | Complete result byte length | Only the result prefix is written; output tail and all workspace bytes remain unchanged |
| `0xffffffff` | Invalid envelope, nested frame or UTF-8 | Entire output and workspace remain unchanged |
| `0xfffffffe` | Insufficient output capacity or result reaching the reserved return-code interval | Entire output and workspace remain unchanged |

The entire envelope and every string are checked before any output write.
UTF-8 validation rejects overlong encodings, surrogates, values beyond U+10FFFF,
standalone continuations and incomplete sequences. NUL and all valid scalar
values remain accepted. The unused workspace can have any capacity, including
zero, and is never read or written. Source bytes are never modified.

## Capacity and executable profile

The standard compiled profile has an 8 MiB input and output boundary. It is a
resource domain, not a new limit on the original Rust `String` semantics. This
source has no hidden per-hint or hint-count quota. Every complete input at the
profile boundary fits the corresponding standard output: replacing each
eight-byte hint length with a seven-byte prefix plus LF does not increase that
part, and both envelope headers are removed. For a nonempty list the output is
exactly input length minus 62 bytes; for an empty list it is input length minus
64 bytes. The generic source separately checks the actual output buffer and the
reserved u32 return interval.

The existing HIA filter packer produces a static Linux x86-64 ELF. It requires no
Python, Rust, libc or dynamic loader at execution time. Python test drivers and
the independent Rust reference are qualification tools. This component performs
no filesystem effects or external calls.

## Qualification and integration

Use the existing generic `NativeBuild.compile` with source
`native/response_hints.hepta`, name `response-hints`, and `standalone="filter"`.
The standard profile and pinned compiler are unchanged. The module registry key
is `response_hints`, its suite is `test_response_hints.py`, and its manifest
environment variable is `HIA_RESPONSE_HINTS_MANIFEST`. Optional
`HIA_RESPONSE_HINTS_CORPUS_DIR` retains the complete semantic input/output streams
and the source-bound native report for the independent original-Rust replay.

The suite executes complete Unicode scalar input, invalid-byte/boundary controls,
maximum standard-capacity input, empty and repeated hints, exact-capacity and
one-byte-short output buffers, failure atomicity and actual static ELF cases.
The corpus contains only actual successful native semantic executions. The
additional malformed/UTF-8/capacity controls are recorded separately and cannot
inflate original-Rust case counts. Captured native receipts do not substitute
for the fresh original-Rust replay or the repository's complete cold/native
qualification.

Production handler activation, complete task-local routing and removal of the
old runtime are not claimed by this component.
