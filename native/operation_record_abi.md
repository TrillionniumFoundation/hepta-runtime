# Internal native operation record owner

`operation_record.hepta` implements binding admission, canonical associated
data, complete byte-level result sealing/opening, and inner record validation
from the original `src/mcp/runtime/operation_crypto.rs` at runtime commit
`a0dcdda1991ec536d5e2d252c006a778993fa566` (Git blob
`0c07318a6d85efb920069ce4f190c4f2ed56e84f`). The original whole-source SHA-256
is `a48463ef35ca41d0aa8ef64fcaeb9d3245773052221789a38d18d52ced891633`.

This is an internal byte component for a trusted scope controller. Its key and
nonce inputs are available only to that controller. They are not public tool
parameters, bearer authentication, or an authorization mechanism. The component
does not generate entropy, reserve nonces, construct/destroy key capabilities,
coordinate locks, persist ledger state, or admit operation replay. The scope
controller must perform and bind those steps. None of the original production
handlers or old-stack removal gates is advanced by this component alone.

## Request ABI

The entry is `f0(readbuf input, mutbuf output, mutbuf private) -> u32`.
All integers in the request header are little endian. The complete input must
remain immutable and at the same length throughout a continuation sequence.

| Offset | Width | Meaning |
|---|---:|---|
| 0 | 8 | ASCII `HRREC001` |
| 8 | 8 | Operation 1–4 |
| 16 | 8 | Reserved zero |
| 24 | 8 | Payload kind: 1 `NativeResult`, 2 `NativeError` |
| 32 | 8 | Accepted timestamp: low 64 bits |
| 40 | 8 | Accepted timestamp: high 64 bits |
| 48–95 | 6 × 8 | Byte lengths of operation ID, owner, tool, policy binding, request binding, ledger identity |
| 96 onward | variable | Those six fields, concatenated in order, then the operation tail |

| Operation | Tail | Successful output |
|---|---|---|
| 1 | Empty | Canonical AAD |
| 2 | Scope AEAD key 32 bytes, reserved nonce 12 bytes, payload | Complete original `HEPTAOP1` packet |
| 3 | Scope AEAD key 32 bytes, complete packet | Authenticated and fully validated payload |
| 4 | Payload | Canonical AAD after the original seal admission checks |

The five identity fields are exactly 64 ASCII lower-hex bytes. The tool is
1–128 ASCII bytes, begins with `a`–`z`, and otherwise contains only `a`–`z`,
`0`–`9`, or `_`. Every u128 timestamp is supported. Non-UTF-8 field bytes cannot
be original Rust `String` values; the native transport rejects them as invalid
bindings and its tests distinguish this extra byte-domain refusal from original
owner comparisons. The unknown-kind and malformed-frame cases likewise belong
to this adapter rather than the original typed enum.

Operation 4 exists for the scope controller's ordering: admit payload and
binding, then acquire entropy and reserve the nonce, then call operation 2 with
that same immutable binding/payload. Operation 2 repeats admission; operation 4
does not create a capability or make subsequent altered input trustworthy.

## Original byte format and ordering

AAD is the following eleven fields, each prefixed by its u32 big-endian byte
length, followed by the complete 16-byte big-endian timestamp:

1. `hepta-runtime/native-operation/result-aad/v1`
2. `HEPTAOP1`
3. `chacha20_poly1305`
4. `serialized-native-sdk-result-family/v1`
5. Operation ID
6. Owner
7. Tool name
8. Policy binding
9. Request binding
10. Ledger identity
11. `native_result` or `native_error`

The inner cleartext is `HOPIN001`, the payload length as u64 big endian,
the payload's 32-byte SHA-256, then the payload. The outer packet is
`HEPTAOP1`, the 12-byte nonce, and ChaCha20-Poly1305 ciphertext including its
16-byte tag. Per-record keys come from the existing KDF owner's operation 9;
this owner adds no hash, KDF, cipher, or tag implementation.

For sealing/preflight, payloads above 1,048,576 bytes fail before binding
validation. For opening, packet sizes outside 84–1,048,660 bytes or a wrong
outer magic fail before binding validation. Then binding/AAD, record key,
AEAD authentication, inner magic, declared payload length, and payload digest
are checked in that order. An authenticated malformed inner record is still
refused. Plaintext is staged privately and copied to output only after all
checks succeed. Empty payload opening is a successful zero-byte result.

For a successful seal, the internal child order follows the original pure work:
derive the record key, hash the payload, then seal the inner record. The explicit
empty-hash sanitation is inserted after that payload hash.

Malformed frame spans and insufficient workspace are adapter admission errors.
Once semantic admission succeeds, output capacity is checked before private
mutation or crypto child calls. Capacity failures have no original Rust
counterpart and are excluded from the original-owner differential corpus.

| Return code | Meaning |
|---|---|
| 0…1,048,660 | Exact output byte count |
| `0xffffffff` | Invalid frame, operation, kind, reserved value, or span |
| `0xfffffffe` | Insufficient output/private capacity |
| `0xfffffffd` | Original `PayloadTooLarge` |
| `0xfffffffc` | Original `InvalidBinding` |
| `0xfffffffb` | Original `IntegrityUnavailable` |
| `0xfffffff8` | Child or continuation contract failure; destroy the entire context |
| `0xffffffe0` | Request the next fixed child call |

## Composition and continuation contract

The record owner is module 1 with a 3 MiB private workspace. The final 256 bytes
are the existing bridge footer, outside its scratch region. Only these child
IDs are authorized:

The initial phase word at private offset zero must be zero. The bridge owns the
footer event/module IDs and persistent sequence; it supplies event 3 and module
ID 1 for this child. A sequence at the u64 maximum refuses without wrapping.

| ID | Owner | Operation(s) | Private bytes |
|---|---|---|---:|
| 2 | `operation_kdf.hepta` | 9, per-record key | 2,048 |
| 3 | `binary_codec.hepta` | 1, payload and empty SHA-256 | 1,184 |
| 4 | `operation_aead.hepta` | 1 seal, 2 open | 512 |

The call mask is 28. Requests and results occupy disjoint spans of the record
workspace. The owner validates the bridge magic, increasing sequence and exact
acknowledgement, child ID, both region IDs, both span offsets/lengths, reserved
value, completion/status, and exact expected returned length before consuming
any result. Opening accepts the AEAD owner's documented authentication refusal;
the same return during sealing is a child contract failure. Hash sanitation
additionally verifies the full known SHA-256 empty digest, not just its length.

`scripts/hia_native_record_build.py` binds all five image sources (including the
test root), their compiler and generic composition packer. The test root's mask
is 2 and its child is record module 1. It converts hexadecimal lines to native
frames and encodes `eight-lower-hex-code:output-hex` responses; it performs no
binding or crypto semantics. It is a fixture under `tests/hia_native`, not a
runtime MCP service. The resulting ELF runs without Python or libc semantic
dispatch. Direct-image tests also transport continuations in Python; their
controller/leaf counts are separate from actual ELF response counts.

## Exact scratch cleanup

Record metadata occupies the low bytes of its private workspace. AAD starts at
512, digest/key slots at 1536–1663, and child request staging at 2048. Child
outputs are aligned after their entire request. The owner records a monotonic
high-water mark covering every written request and response span. On each
terminal path after private admission it clears every byte from zero through
that mark. This also covers a large earlier payload after shorter sanitation
or key requests overwrite only the beginning of the request staging area.
Bytes beyond the high-water mark remain unchanged; the bridge footer preserves
its sequence/lifecycle state. Pure AAD/preflight and admission refusals do not
write scratch. Output tails remain untouched. Read-only caller input is owned
and eventually cleared by the trusted caller, not this component.

KDF and AEAD clear all their declared private bytes on their completed success
or documented AEAD authentication failure. The codec retains SHA working
state, so this owner explicitly runs operation 1 on an empty payload after
every payload hash, including a hash whose returned length is wrong. Its
1184-byte workspace becomes deterministic and independent of the prior payload:

| Bytes, inclusive | Empty-hash overwrite |
|---|---|
| 0–511 | `initialize` writes all 64 eight-byte round-constant slots |
| 512–1023 | `compress` writes all 64 eight-byte message-schedule slots: 16 decoded words and 48 expanded words |
| 1024–1087 | `initialize` replaces all eight chaining slots, then empty-block compression replaces them with the empty digest state |
| 1088–1095 | Total byte count is replaced by zero |
| 1096–1103 | Pending-byte count is replaced by zero |
| 1104–1111 | Phase marker is replaced by one |
| 1112–1175 | All 64 pending bytes are zeroed; empty finalization writes `0x80`, zero padding, and zero length |
| 1176–1183 | The eight-byte workspace magic is replaced |

`initialize` alone does not replace the schedule; completion of empty-block
compression is essential. The tests first demonstrate a known synthetic secret
inside the pending buffer after its payload hash, then compare **every one of
the 1184 bytes** after empty hashing with a fresh independently initialized
empty-hash workspace. They also retain 19 untouched tail bytes and external
canaries, and inspect actual child workspaces across record seal/open calls.

A forged/denied callback cannot provide a trustworthy route to additional child
cleanup. Such a callback clears accessible record scratch and returns the fatal
child code; the trusted adapter must retire the entire composition, including
child mappings. Reusing a failed child context is outside the ABI. Changing
input/workspace capacities between callbacks also violates the stable-buffer
contract. There is no claim about register/stack erasure, asynchronous termination
cleanup, timing behavior, or constant-time qualification.

## Reference evidence

The locked Cargo oracle includes the complete unchanged original crypto module
and appends a test-only access shim. It calls actual `TrustedResultBinding::new`,
`aad`, `seal_with_entropy`, and `open`. Synthetic entropy supplies the exact
fixture nonce for sealing. The preflight comparison calls the actual original
seal with entropy that deliberately refuses: valid admission reaches that point
exactly once, without reserving a nonce; earlier original errors reach it zero
times. Private synthetic scope keys exercise byte ownership, and additional
fixtures invoke the actual verified-token constructor and check its derived key.

The corpus records native output/status, source and image hashes, original
source SHA, complete Cargo/shim identities, the composition manifest, and
independent Python crypto distribution/version. The retained native observations
and actual original Rust comparison are distinct receipts. Neither a Python
projection nor merely compiling the Rust binary is an original-owner PASS.
