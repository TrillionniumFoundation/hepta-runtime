# Private local exclusive-create owner

This HIA owner implements the blocking filesystem chain of the current target's
`create_local_file`: reserve a new pathname, write the complete byte slice, and
finish all pending writes before success. The source target is commit
`737acf6f901e46c57b0b4374e323e0d1132e0d49`; the complete original file and exact
function slice are pinned in `local_create_file_component.json`.

The Linux x86-64 executable contains this HIA image and a fixed syscall bridge.
HIA chooses exclusive-open flags, write boundaries, retries, error precedence
and descriptor retirement. The bridge executes only the admitted `openat`,
`write` and `close` effects and returns their actual kernel completions. The
HIA packer emits the complete static executable. There is no runtime Python,
Rust, libc, dynamic loader or semantic fallback.

## Ownership and scope

Paths are trusted private Local path bytes. Raw Unix bytes, NUL refusal,
symlink resolution, existing paths, permissions and umask remain in the original
domain. The open flags are `O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC`, with mode
`0666` filtered by the actual umask. Existing paths, including dangling
symlinks, cannot authorize truncation. Writes use Tokio's locked 2 MiB chunk
size, advance on partial writes, retry EINTR, and preserve a write error across
close. A zero-byte write is WriteZero. Open retries only EINTR. The owned
descriptor is retired before one close attempt; close errors do not replace
the original result and close is never retried.

This owner qualifies a blocking leaf. A same-owner development async entry is isolated behind HLCARQ01. Its
controlled scheduler, buffered acceptance and cancellation qualify separately
from this preserved blocking contract. The full `create_file_spec` existence diagnostic, parent-directory
creation, remote branch, `note_create`, text-editor dispatch and public
authorization are not supplied by this private interface. Production activation,
whole-runtime replacement and old-stack-removal flags remain false.

## Borrowed request

The entry is `f0(readbuf, mutbuf, mutbuf) -> u32`. Integers are little-endian u64.
The 64-byte header is followed by exactly the path and content bytes.

| Offset | Meaning |
| ---: | --- |
| 0 | Eight-byte magic `HLCREQ01` |
| 8 | 1 start, 2 resume |
| 16 | Raw path byte length |
| 24 | Content byte length |
| 32–63 | Four zero reserved words |
| 64 | Path, then content |

The workspace needs `513 + path_length + content_length` bytes; output needs
48 bytes. The initial call copies the complete input into owned workspace.
Every resume checks the exact same path and content before consuming an effect.
Insufficient borrowed capacity is a private capacity refusal, not a new
filesystem error or public content quota. The native process uses checked
dynamic mappings sized to the actual request.

| Return | Meaning |
| --- | --- |
| 48 | Complete typed result |
| `0xfffffffd` | One fixed effect pending |
| `0xfffffffe` | Insufficient borrowed capacity |
| `0xffffffff` | Invalid frame or continuation |

Invalid/capacity refusals preserve the entire output and workspace. Pending
effects do not publish partial output. Completed results can be replayed without
repeating effects. A new start cannot replace a live continuation.

## Private state and effects

The state magic is `HLCREW01`; phases are open 1, write 2, close 3 and done 4.
Offsets 16 through 88 hold sequence, path length, content length, owned extent,
descriptor token, written count, current chunk end, result kind, errno and the
retiring close token. Bytes 96–127 and 224–511 remain reserved zero. The copied
path starts at 512, followed by one NUL and then the copied content.

The 96-byte effect at offset 128 contains `HLCREF01`, sequence, action, four
arguments, completion flag, raw syscall result, positive errno, result token
and one reserved zero word. Only these actions are admitted:

| Action | Arguments | Completion |
| --- | --- | --- |
| 1 open | Path offset 512, path length, fixed flags `0x800c1`, mode 0666 | Owned opaque token or raw negative errno |
| 2 write | Held token, exact copied-content offset, current chunk remainder, zero | Count no greater than requested, or raw negative errno |
| 3 close | Retiring token, zero, zero, zero | Zero or raw negative errno; token already retired |

The bridge checks phase, sequence, token custody and every span independently.
Public input cannot name a syscall, raw file descriptor or address. Sequence
wrap uses the full u64 domain and introduces no effect-count quota. Completed
effect fields must be internally consistent before HIA consumes them.

## Result and static transport

The result is exactly 48 bytes: `HLCRER01`, extent 48, result kind, errno,
successfully written bytes, reserved zero. Kinds are success 0, OS error 1,
interior-NUL InvalidInput 2 and WriteZero 3. The written count on an error is
private observational state; the original Rust Result exposes only the error.
Original comparisons therefore compare error kind/errno and complete resulting
filesystem bytes, and compare the count directly on successful calls.

The static fixture accepts one u64 request length plus that request. It returns
a u64 result extent followed by the result; an invalid/capacity refusal returns
only its u64 code. Stderr retains the exact 96-byte actual kernel effect records.
The input mapping is read-only during HIA execution. Transport failures retire
any bridge-owned descriptor, and SIGPIPE is ignored so failed publication takes
that cleanup path. EOF/framing and the native caller's scheduler are separate
from the original filesystem result.

The native state suite records every complete before/after borrowed array and
guard, and labels injected completions explicitly. Independent filesystem
processes retain all inputs, outputs, effect records and complete before/after
file contents. Fresh locked Rust 1.95.0 executes the unchanged target function.
Two live-process race controls require exactly one creator and one EEXIST
result with the successful caller's complete bytes.

## Segmented async candidate

The first entry delegates HLCREQ01 to the original f0; all sixteen original
function ASTs and names remain exact. HLCARQ01 uses the same 64-byte path/content
shape, a private invocation generation and commands for initialize, poll, real
queue admission, worker continuation, inline close, drop, real reap and poll
continuation. Metadata begins after the original owned core extent. Native
mechanism calls are serialized; real syscalls run outside that mutex.

A successful queue advances accepted bytes, while core written bytes remain
actual completed bytes. A WRITE ticket keeps its original two-MiB end even when
the core prepares the next effect. Cancellation cannot split one active poll,
and cannot truncate an already admitted chunk. Ready orphan descriptors close
inline before cancellation is published; an in-flight worker retains its input
and descriptor until real completion and exactly one close. Real wait/reap
precedes backing retirement. Runtime shutdown, panicking blocking tasks,
arbitrary cooperative-budget behavior and public handler/cache integration
remain outside this candidate's current qualification.
