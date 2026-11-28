# Native operation AEAD byte primitive

`operation_aead.hepta` owns the ChaCha20-Poly1305 byte transformation used by
the original operation result crypto owner. The construction follows
[RFC 8439, section 2.8](https://www.rfc-editor.org/rfc/rfc8439#section-2.8).
Its entry is the ordinary three borrowed-buffer HIA ABI: immutable input,
mutable output, and an independent mutable workspace. All three spans must
be disjoint, as required by the native module admission boundary.

This primitive does not authenticate a bearer, create a trusted binding,
generate or reserve nonces, manage crypto scopes, frame retained records,
or own the operation ledger. Callers must supply a 32-byte key and a
12-byte nonce; nonce uniqueness for each key belongs to the scope owner.
No constant-time implementation qualification is asserted by these tests.

## Input frame

All header integers are unsigned little-endian. The entire input must have
exactly the declared length; trailing bytes are refused.

| Offset | Bytes | Meaning |
| --- | ---: | --- |
| 0 | 8 | ASCII `HRAEAD01` |
| 8 | 8 | Operation: 1 encrypt, 2 decrypt |
| 16 | 8 | Reserved; must be zero |
| 24 | 8 | Associated-data length, at most 1,048,576 |
| 32 | 8 | Plaintext or ciphertext length, excluding the tag; at most 1,048,624 |
| 40 | 32 | Key |
| 72 | 12 | Nonce |
| 84 | 4 | Reserved; must be zero |
| 88 | variable | Associated data, followed by plaintext for encryption or ciphertext plus the 16-byte tag for decryption |

The plaintext ceiling equals the original 1 MiB result ceiling plus its
48-byte inner record header. The additional-data ceiling is an explicit
primitive bound, larger than the original trusted result binding encoding.
Neither ceiling changes the separate original crypto owner's admission.

Encryption returns ciphertext followed by the complete 16-byte tag.
Decryption returns only the plaintext. Empty plaintext is supported and
therefore successful decryption may return zero with a zero-capacity output.

## Return values and mutation

| Return | Meaning | Output | Workspace |
| --- | --- | --- | --- |
| 0 through 1,048,640 | Exact successful output byte count | Exactly the returned prefix written; tail preserved | First 512 bytes wiped; tail preserved |
| `0xffffffff` | Invalid frame, operation, reserved field or exact length | Preserved | Preserved |
| `0xfffffffe` | Insufficient output or workspace capacity | Preserved | Preserved |
| `0xfffffffd` | Declared associated-data or plaintext ceiling exceeded | Preserved | Preserved |
| `0xfffffffc` | Authentication failed | Preserved, including the entire plaintext-sized prefix | First 512 bytes wiped; tail preserved |

Admission order is minimum header, magic and reserved fields, operation,
declared ceilings, exact frame length, then capacities. No admission failure
touches either mutable buffer. A valid frame requires at least 512 workspace
bytes. The declared 512-byte workspace is erased on both authenticated
outcomes. This check does not certify erasure of CPU registers or compiler
stack spills. Input key bytes and successful output remain under the
caller's lifetime policy.

Authentication covers the complete additional data, ciphertext, RFC padding,
and both 64-bit lengths. The implementation compares every tag byte before
the final authentication decision. Decryption begins only after that
decision succeeds; invalid tags never produce partial plaintext.

## Internal representation

ChaCha uses sixteen unsigned 32-bit words held in 64-bit slots, ten double
rounds, and explicit masking after modular additions and rotations.
Counter zero derives the one-time Poly1305 key; message encryption starts
at counter one. The bounded input cannot exhaust the 32-bit block counter.

Poly1305 uses five 26-bit limbs with clamped key limbs. Products and carry
values fit checked unsigned 64-bit arithmetic. Each RFC AEAD padded segment
block is a full 16-byte Poly1305 block. The final block contains the two
original lengths. Final reduction uses fixed carry passes and mask-based
selection, followed by the 128-bit pad addition.

| Workspace bytes | Use |
| --- | --- |
| 0–127 | Original ChaCha state |
| 128–255 | Working ChaCha state |
| 256–319 | Serialized ChaCha block |
| 320–351 | One-time Poly1305 key |
| 352–391 | Five clamped key limbs |
| 392–431 | Five accumulator limbs |
| 432–447 | Padded authentication block |
| 448–463 | Computed authentication tag |
| 464–511 | Reserved and included in the final wipe |

## Evidence scope

The native suite compares actual HIA images with an independent
ChaCha20-Poly1305 implementation and the published RFC known answer. It
checks both block sizes, empty inputs, maximum declared inputs, independent
random inputs, all tag byte positions, modified key/nonce/data/ciphertext,
capacity boundaries, and buffer mutation rules. A separate locked Cargo
recipe replays exported cases against ring, the original runtime's AEAD
library. Its record fixtures call the complete unchanged original seal/open
owners with deterministic synthetic entropy, including rejected tags.
Standalone ELF cases execute with an empty `PATH`.

These byte primitive results do not certify nonce management, original
record framing, scope clone sharing, mutex failure behavior, entropy effects,
or production activation. Those must close in their respective owners.
