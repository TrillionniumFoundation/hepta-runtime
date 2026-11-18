# Native SHA256 and Base64 byte owner

`binary_codec.hepta` implements bounded SHA256, resumable SHA256 state, canonical
Base64 encoding and three explicitly selected Base64 decoding policies. Its `f0`
entry has the common borrowed-byte signature `(readbuf, mutbuf, mutbuf) -> u32`.
All payload computation executes in HIA-produced machine code. The component
does not open files, publish writes, check file versions, own upload transactions
or replace an existing production tool handler.

## Source ownership

The original binary tools are bound to runtime baseline
`a0dcdda1991ec536d5e2d252c006a778993fa566`:

| Original owner | Git blob | Relevant behavior |
|---|---|---|
| `src/mcp/runtime/binary.rs` | `7195d29297e018be1b640f6ad5caab02738a87a5` | 1,398,104-byte encoded write/upload envelope |
| `src/mcp/runtime/binary_file.py` | `e5dddd844cb9ab869f4784a93f228a8a5ac91a74` | `hashlib.sha256`, canonical encoding, `b64decode(validate=True)`, 1 MiB chunks |
| `src/mcp/runtime/file_metadata.py` | `a289f7c52a554f0c299541b932fcf30fba9251f5` | SHA256 of attribute/ACL byte values |
| `src/mcp/runtime/inode_patch.py` | `25bdc18a30bfe23e84f9b25a5e77dd761841d5cd` | SHA256 and strict Base64 within the existing inode transaction owner |

The SHA scheduling and compression functions are reused from Hepta's
`examples/hia_bootstrap/sha256_stream.hepta` at commit
`f33d8da316de8fdf27b504371f1a5310997ff548`. Its source SHA256 is
`5818184f4decbde6a56741238a9d017fda66a3ed41136f9ceb9533a81c552a20`.
Functions `f1`–`f4` are composed by changing only function names and direct-call
targets. Their operations, blocks, constants, scalar types and control flow are
unchanged. `binary_codec_composition.json` records this relocation and canonical
function hashes; the tests reverse the relocation and compare those hashes to
the pinned upstream HIA. The wrapper owns framing, compact state serialization,
message delivery, final padding and Base64 policy.

## Request frame and operations

Every request starts with a 24-byte header:

| Bytes | Meaning |
|---|---|
| 0–7 | ASCII `HRCODEC1` |
| 8–15 | Operation, unsigned little-endian u64 |
| 16–23 | Reserved u64, exactly zero |
| 24 onward | Operation payload |

| Operation | Payload | Result |
|---|---|---|
| 1 | Raw bytes, at most 1 MiB | 32-byte SHA256 digest |
| 2 | Raw bytes, at most 1 MiB | 64 lowercase ASCII hexadecimal digest bytes |
| 3 | Empty | Initial 128-byte SHA256 state |
| 4 | State followed by at most 1 MiB of new bytes | Updated 128-byte state |
| 5 | Exactly one state | 32-byte final digest |
| 6 | Exactly one state | 64 lowercase hexadecimal digest bytes |
| 7 | Raw bytes, at most 1 MiB | Standard `A–Z a–z 0–9 + /` Base64 with canonical `=` padding |
| 8 | Encoded bytes, at most 1,398,104 bytes | Observed desktop-compatible strict decode |
| 9 | Encoded bytes, at most 1,398,104 bytes | Strict padding decode; nonzero pad bits accepted |
| 10 | Encoded bytes, at most 1,398,104 bytes | Canonical decode, including zero pad bits |

Decoded output is limited to 1 MiB for all three policies. An encoded payload of
1,398,104 alphabet bytes can decode to 1,048,578 bytes and is therefore rejected,
although the encoded-length envelope itself fits. Empty input is valid for
hashing, encoding and decoding. SHA state updates may be empty.

SHA operations require at least 1,184 workspace bytes, retaining the upstream
SHA workspace layout. Base64 operations require no workspace and leave any
supplied workspace untouched. The caller controls all three disjoint buffers.

## Decoding policy is explicit

The original `binary.rs` delegates decoding to Python. It does not use Rust's
default Base64 decoder. Actual observations found a relevant difference:

| Encoded input | Operation 8 | Operation 9 | Operation 10 |
|---|---|---|---|
| `AAAA` | Three zero bytes | Same | Same |
| `AAAA=` | Three zero bytes | Reject | Reject |
| `AA==` | One zero byte | Same | Same |
| `AA===` | Reject | Reject | Reject |
| `Zh==` | ASCII `f` | ASCII `f` | Reject: nonzero pad bits |
| `_w==` | Reject | Reject | Reject |
| Embedded/trailing whitespace or NUL | Reject | Reject | Reject |

Operation 8 matches the observed target's CPython 3.12.3 expression
`base64.b64decode(data, validate=True)`: surplus `=` bytes are accepted only
after a nonempty sequence of complete four-character groups. Partial final
groups still require exactly one or two padding bytes. Operation 9 matches the
observed CPython 3.12.14 policy, which also rejects surplus padding after complete
groups. Both accept nonzero unused bits in the last sextet. Operation 10 requires
the unique representation produced by operation 7. No operation accepts the
URL-safe `-`/`_` alphabet, omitted required padding, leading padding or data
after padding. Native execution does not inspect the host Python version.

The test suite directly compares the applicable declared profile with the
running Python decoder, records the observed profile, and checks all profiles
against the independent Rust reference. A future tool adapter must choose its
declared policy; changing the accepted grammar implicitly would change existing
write/upload behavior.

## Serialized SHA state

The 128-byte value is independent of buffer addresses and chunk partitions:

| Bytes | Meaning |
|---|---|
| 0–7 | ASCII `HSHA2561` |
| 8–15 | Total supplied bytes, little-endian u64 |
| 16–23 | Buffered byte count, equal to total modulo 64 |
| 24–55 | Eight chaining words, each little-endian u32 |
| 56–119 | Pending bytes followed by zeros through the end of the 64-byte field |
| 120–127 | Reserved, exactly zero |

The total is bounded by `2^61 − 1`, so the SHA256 64-bit bit-length field cannot
overflow. Before the first complete block, the chaining words must equal the
SHA256 initial constants. State headers, lengths, unused bytes and reserved
bytes are validated before output or workspace writes. The chaining words of
a state beyond its first block are caller-owned continuation data; the state
format does not authenticate a history of earlier chunks.

Finalization works on a private workspace copy. It does not consume or mutate
the input state. The same state can be finalized repeatedly, continued with new
input, or forked into different suffixes. Equal message prefixes produce equal
serialized states regardless of how those prefixes were split across updates.
Files larger than one chunk are represented by repeated updates, rather than
an oversized one-shot request.

## Returns and write guarantees

Successful calls return the number of output bytes, including zero for an empty
Base64 result. The output tail and all input bytes remain unchanged. SHA
operations use only the first 1,184 workspace bytes; their workspace tail remains
unchanged.

| Return | Meaning |
|---|---|
| `0xffffffff` | Malformed frame/state, unsupported operation or invalid Base64 grammar |
| `0xfffffffe` | Insufficient output or SHA workspace capacity |
| `0xfffffffd` | Encoded, decoded, chunk or total SHA length bound exceeded |

All refusals leave both the complete output buffer and workspace unchanged.
These are typed byte-owner results; the surrounding filesystem API's existing
diagnostic text, authorization, metadata checks and publication semantics remain
with that API.

## Reproducible checks

`tests/hia_native/test_binary_codec.py` accepts `HIA_CODEC_MANIFEST`,
`HIA_HEPTA_DIR` and optional `HIA_CODEC_CORPUS_DIR`. Without a selected manifest,
it builds once with `HIA_BUILD_ROOT`. The build uses the normal native filter
packer and checks the resulting executable with an empty `PATH`.

Seven suites exercised 22,517 direct native calls: SHA256 vectors including one
million `a` bytes, block/padding boundaries, all tested two-part splits, random
partitions, repeatable/forked finalization, a 9 MiB stream, malformed state and
capacity failures, short Base64 grammar combinations, noncanonical bits and
exact 1 MiB boundaries. The retained corpus contains 16,965 reference cases.

The independent Rust oracle uses `base64 = 0.23.1` and `sha2 = 0.11.0`, matching
the runtime's resolved crate versions, with an explicit Cargo lockfile. Its
SHA stream checks reconstruct message digests independently; compact-state
protocol validation is also tested directly by the native suite. An actual
Rust 1.95.0 run compared all 16,965 cases successfully. Actual desktop CPython
3.12.3 additionally matched all 5,380 operation-8 cases. These are replays of the
captured native cases and do not add new native-call coverage. The observed
result and original job identity are retained in
`binary_codec_independent_comparison.json`.
