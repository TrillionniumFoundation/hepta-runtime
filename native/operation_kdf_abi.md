# Native operation key derivation and binding bytes

`operation_kdf.hepta` is a pure HIA byte owner for HMAC-SHA256, HKDF-SHA256 and
the deterministic key/domain calculations in `operation_crypto.rs`. SHA256
functions are imported from the already qualified `binary_codec.hepta` by
function and call-target relocation only. The source composition proof and
test setup reverse that relocation and compare complete function structures.

This component is an internal primitive. It is not an MCP tool and does not
authenticate a bearer token, construct a trusted result binding, reserve a
nonce, encrypt a result, install a scope, authorize replay or persist a ledger.
The existing operation crypto owner remains responsible for those contracts.
Key outputs belong in a trusted caller's private memory; they must not become
public protocol results. This primitive does not replace the original scope's
non-exportable interface.

## Entry and frame

The entry uses `(readbuf, mutbuf, mutbuf) -> u32`. The three buffers must be
disjoint. The request starts with the following 56 bytes, followed by fields
`A`, `B` and `C` in that order. All header integers are unsigned little-endian.

| Offset | Field |
|---|---|
| 0 | Eight bytes `HRKDF001` |
| 8 | Operation number |
| 16 | Reserved u64, exactly zero |
| 24 | Byte length of A |
| 32 | Byte length of B |
| 40 | Byte length of C |
| 48 | Requested output byte length L |

Each field is at most 1 MiB. The request must contain exactly the declared
bytes, with no trailing bytes. The operation-specific output length is checked
before writing either mutable buffer.

| Op | A | B | C | L / successful result |
|---|---|---|---|---|
| 1 | HMAC key | Message | Empty | 32 raw HMAC-SHA256 bytes |
| 2 | HKDF salt | Input key material | Empty | 32 raw extracted key bytes |
| 3 | Exactly 32 extracted key bytes | HKDF info | Empty | 0..8,160 expanded bytes |
| 4 | HKDF salt | Input key material | HKDF info | 0..8,160 extracted and expanded bytes |
| 5 | Already verified token bytes | Empty | Empty | 128 bytes: AEAD, request, idempotency and policy keys, 32 bytes each |
| 6 | Exactly 32 request-key bytes | Nonempty canonical context, at most 1 MiB | Empty | 64 lowercase hexadecimal binding bytes |
| 7 | Exactly 32 idempotency-key bytes | Nonempty private idempotency key, at most 128 bytes | Empty | 64 lowercase hexadecimal binding bytes |
| 8 | Exactly 32 policy-key bytes | Nonempty canonical policy, at most 1 MiB | Empty | 64 lowercase hexadecimal binding bytes |
| 9 | Exactly 32 AEAD-key bytes | 64 lowercase hexadecimal operation-id bytes | 64 lowercase hexadecimal ledger-id bytes | 32 per-record key bytes |

Operation 5 preserves the original token byte validation: 32..4,096 bytes,
each within ASCII 33..126. Passing this syntax check does not verify that a
token was authorized. The caller must already have verified the exact bearer.
Operations 6..8 consume caller-owned canonical bytes; this module does not
canonicalize JSON or choose which private execution and policy context to bind.

## Exact original domain separation

The original source is pinned to runtime commit
`a0dcdda1991ec536d5e2d252c006a778993fa566`, file
`src/mcp/runtime/operation_crypto.rs`, SHA256
`a48463ef35ca41d0aa8ef64fcaeb9d3245773052221789a38d18d52ced891633`.
The composition record retains all seven exact salt/domain strings.

Operation 5 uses the original extract salt and four distinct expansion labels.
Operations 6..8 authenticate the big-endian u32 domain length, domain bytes,
big-endian u64 input length and exact input bytes in that order. Operation 9
extracts from the AEAD key using the original record salt and expands with the
record domain followed by the operation id and ledger id. Their fixed lengths
and lowercase hexadecimal admission are retained.

The general HMAC and HKDF primitives follow
[RFC 4231 test vectors](https://www.rfc-editor.org/rfc/rfc4231) and
[RFC 5869](https://www.rfc-editor.org/rfc/rfc5869). Empty salt has the same HMAC
key block as a zero-filled SHA256 output. HKDF expansion uses counter bytes
1 through 255; 8,160 is the maximum output for a 32-byte SHA256 digest.

## Memory and refusal contracts

The workspace must contain at least 2,048 bytes. On success, HIA clears all
2,048 used workspace bytes, including the key block, intermediate digests,
extracted key, previous expansion block and temporary domain bytes. It leaves
the workspace tail and unused output tail unchanged. The caller still owns
the input key bytes and any requested key output and must manage their lifetime.
No constant-time qualification or whole-process secret-erasure claim is made.

| Return | Meaning |
|---|---|
| 0..8,160 | Number of output bytes |
| `0xffffffff` | Malformed header, unsupported operation or invalid operation-specific input |
| `0xfffffffe` | Insufficient output or workspace capacity |
| `0xfffffffd` | One of the general field/output length limits exceeded |

All refusals leave the complete output and workspace unchanged. Admission order
is minimum header, magic/reserved/op, general bounds, exact frame length,
operation-specific validation, then capacities. Input bytes are never modified.
The module has no operating-system effects, mutable global state or fallback.

## Verification

`test_operation_kdf.py` checks published HMAC/HKDF vectors, block/key/padding
boundaries, maximum HKDF counter, deterministic random inputs, original domain
framing, exact original token/idempotency bounds, capacity refusals, workspace
clearing and standalone ELF execution with an empty `PATH`. A separate actual
Rust reference must run before the component can receive aggregate qualification.
Standard primitive comparisons and original operation-binding comparisons are
reported separately. These checks do not qualify AEAD or operation ownership.
