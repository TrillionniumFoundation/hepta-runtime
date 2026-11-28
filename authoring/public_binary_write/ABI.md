# Native public binary-write remote helper

This Linux x86-64 one-shot program composes the full original locked write
operation with an HIA path owner and fixed syscall adapters. Business decisions
execute in ten HIA images. Runtime Python, Rust and libc are not required.
The calling gateway owns host authorization, configured write-root selection,
the original jobs::audit call before SSH, SSH admission/lifetime, fixed
redaction, JSON decoding and final public response serialization.

## Stdin and process result

All scalar words are little-endian u64. HBWRQ001 has a 96-byte header.

| Offset | Required field |
| --- | --- |
| 0 | HBWRQ001 |
| 8 | command 1 |
| 16 | zero sequence |
| 24 | mode 1 |
| 32 | configured root UTF-8 byte length |
| 40 | original path UTF-8 byte length |
| 48 | expected_version UTF-8 byte length |
| 56 | data_base64 UTF-8 byte length |
| 64, 72, 80 | zero |
| 88 | exact sum of the four payload lengths |

The payload is the complete root, original path, expected_version and
data_base64, in that order. No length prefix, NUL terminator, numeric descriptor
or caller-selected executable is accepted. All four values must be valid UTF-8.
The gateway supplies the root from its admitted configuration; the root in this
private frame is not an independent public authorization.

Success writes the complete original JSON value plus LF to stdout and exits
zero. Business failure writes the original exception class, colon, space,
exception string and LF to stderr and exits one. Private framing/resource
failure exits 111 without a business result. Native JSON whitespace and member
ordering may differ; the public gateway performs the original JSON-value decode
before serializing its result. The successful value has written, size, version,
sha256 and mode, all measured from the actual operation.

The unchanged original public typed caller applies its encoded-string bound.
The locked HIA write owner separately applies the original decoded 1 MiB limit,
after expected-version checking and strict decoding. The private fixed native
resource ceilings remain input/output 128 MiB and work 256 MiB; they do not
replace the original business bounds.

## Owned effects and ordering

The outer HIA owner retains the complete original PurePosixPath normalization,
root containment, sidecar exclusion, directory order, error replacement and
final parent close. Six complete existing public-file-info walk functions,
twelve normalization/buffer helpers, error_class and the original UTF-8 HIA
function are admitted by exact AST or complete IR equality. The new entry,
layout and write-child protocol carry the additional version and Base64 fields.

The fixed adapter holds real FD-plus-one tokens for the two directory slots.
Only the HIA-selected slash open, directory openat, owned close, orphan transfer
and one immediate repeat of a failed close can execute. A failed old-directory
close leaves the newly opened child in the process-lifetime orphan pool, then
performs the original repeated close. FD zero remains ordinary.

The write callable borrows the actual held parent. It owns the lock/current/temp
descriptors, performs SHA256 of the actual basename for the lock name, opens and
validates the private lock, preserves the original append-wrapper behavior,
takes LOCK_EX, checks expected_version, decodes Base64, checks the decoded limit,
obtains UUID4 from the one process entropy context, creates and writes the temp,
fsyncs/closes it, invokes publication with metadata preservation, fingerprints
the result, unlinks the temp and closes the lock. Parent close follows the
complete child result and can replace an earlier failure. All retries, partial
writes and cleanup precedence remain in HIA.

The final basename is not rejected for NUL before entering the write body.
As in the current original, its hash and private lock are created first; the
expected-version current-file open then raises the path-conversion error.
The body result is copied completely before its native output loan is released.
Write, publication and fingerprint output arenas are reserved for the complete
nested input before first admission, without replaying a started command.

One process orphan pool and one serialized entropy context are created for the
helper. The write context never destroys either; they live until OS process exit.
SIGPIPE and SIGXFSZ are ignored as in the measured original interpreter.
The helper arms parent-death SIGKILL and checks its original parent before
reading stdin.

## Explicit current-interpreter profiles

The original qualified source under
qualification/binary_write_body/v1/native_build stays unchanged, including its
74-file manifest and complete historical evidence.

The current original reference is CPython 3.14.4 on Linux x86-64. Two separately
named HIA profiles adapt the earlier 3.12.3 component:

* public_binary_write_body_profile preserves 42 of the original 43 complete
  functions. Only literal_embedded changes from "embedded null byte" to
  "open: embedded null character in path", at the original open boundary.
  Replacing that one function and module name restores the complete original IR.
* public_binary_write_base64_profile preserves 17 of the original 19 complete
  functions. It replaces base64_scan and emit_error and adds one padding-error
  literal. The source authority is CPython v3.14.4 Modules/binascii.c,
  binascii_a2b_base64_impl, Git blob
  1030eb15f4169c691ad7254542f4992ce75ef3c7. The exact retained source is bound in
  verification.json. Strict padding decisions follow that function, including
  excess padding, invalid alphabet after padding, and single-character-length
  error precedence. UTF-8/ASCII admission, byte decoding, existing error
  literals, buffer admission and untouched workspace remain fixed.

The metadata, codec, stat-version, structured-error34, publication,
fingerprint/read67 and entropy HIA sources and their fixed adapters are
byte-identical to the admitted originals. These seven images plus the two
profiles and outer walk form the ten runtime images.

## Internal continuation protocol

The outer owner has (readbuf, mutbuf, mutbuf) -> u32. It returns 64 for HBWRR001,
0xffffffff for invalid private input/state and 0xfffffffe for output below
64 bytes. HBWRR001 has kind at 8, sequence at 16, operation at 24, arguments at
32/40/48 and payload length at 56.

Kinds 0 and 3 are complete terminal JSON or a complete nested
HBRDS001/HMDSR001/HOSER001 error. Kinds 4/5 request work/output growth, with the
required extent at 32 and all other nonmagic/type fields zero. Kind 1 selects
the five fixed directory effects above. Kind 2/op 1 passes HBWTQ001 to the fixed
write callable with a separately borrowed parent capability and zero external
FD word. expected_version is always the original required string.

Replies use HBWRQ001 command 2, exact outstanding sequence, actual signed
syscall result or full child extent at 24, zeros at 32..80 and complete payload
after byte 96. A repeated growth continuation must reproduce every saved
reply byte, extent, sequence and return. The owner keeps separate saved-reply,
nested-input, error and successful-result arenas.

## Build and verification

The builder reproduces both authoring recipes, admits all qualified source
bytes/Git blobs/modes, compiles twelve HIA sources with the fixed B3 compiler,
assembles a relocation-free adapter, and invokes the actual HIA linker and
image packer. It compares the complete packed executable against the fixed
layout calculation. Production contains no journal or fault-installation path.

Run:

    python3 -I -B scripts/hia_native_public_binary_write.py \
      --source REPOSITORY --hepta PINNED_HEPTA \
      --bootstrap ADMITTED_BOOTSTRAP --output FRESH_BUILD
    python3 -I -B tests/hia_native/test_public_binary_write.py \
      --source REPOSITORY --build FRESH_BUILD --output FRESH_CONTROLS

The nine actual control methods cover complete original/native write pairs,
metadata/hard-link behavior, actual RLIMIT partial writes and cleanup,
FD zero, complete observation, real outer close EIO, malformed frames and owner
capacity, strict decoder full-buffer pairs, real cooperative-lock blocking and
release, and actual parent-death kill/reap with the stdin writer retained.

Each successful returned version is first compared to the complete actual
post-write stat of its own final file. Only then are these distinct OS identities
mapped to the same final-file role for cross-process JSON equality. All other
JSON fields, complete exception stderr and every final filesystem entry/content/
mode/xattr/link-count are compared. This normalization does not supply a native
result or replace an actual filesystem observation.

The first source-mode admission failure, first decoder-author missing-callee
failure, initial decoder mismatch, and initial observer-fixture descriptor
failure are retained. Fixing the fixture changed only module preparation:
all nine test methods remained exactly identical by AST. No original test,
application source, budget or failure record was changed.

See verification.json for exact source/artifact/evidence identities.
This helper does not itself qualify public jobs::audit, network SSH,
default handler routing, other platforms or the entire runtime.
